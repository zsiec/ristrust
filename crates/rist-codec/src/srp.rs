//! SRP-6a (Secure Remote Password) over SHA-256, the RFC 5054 PAD-compliant
//! variant, byte-exact with libRIST v0.2.18-rc1. Ported from ristgo `internal/srp`.
//!
//! It is the cryptographic engine behind RIST Main-profile EAP-SRP authentication:
//! the [`eap`](crate::eap) layer drives a [`Client`] (authenticatee) and [`Server`]
//! (authenticator) through the SRP-6a message exchange and derives the shared
//! session key K.
//!
//! The protocol, with H = SHA-256, "|" = concatenation, all bignums big-endian on
//! the wire, and PAD(x) = x left-zero-padded to len(N) bytes (256 for the 2048-bit
//! group):
//!
//! - `x  = H( salt | H( username | ":" | password ) )`
//! - `k  = H( PAD(N) | PAD(g) )`
//! - `v  = g^x mod N`  (the verifier)
//! - `A  = g^a mod N`  (client)
//! - `B  = (k*v + g^b) mod N`  (server)
//! - `u  = H( PAD(A) | PAD(B) )`
//! - client `S = (B - k*(g^x mod N)) ^ (a + u*x) mod N`
//! - server `S = (A * (v^u mod N)) ^ b mod N`
//! - `K  = H( S )`  (S at its NATURAL minimal byte length, NOT padded)
//! - `M1 = H( (H(N) XOR H(g)) | H(I) | salt | A | B | K )`  (N,g,salt,A,B minimal)
//! - `M2 = H( A | M1 | K )`  (A minimal)
//!
//! PAD scope is the one subtlety: libRIST's PAD-compliant mode (the 0.2.16+
//! default, `hashversion=1`) pads only the operands of `k` and `u` to len(N). In
//! the M1/M2 component hashes N, g, salt, A, B are written at their minimal
//! big-endian length, and K hashes S at its minimal length too. This module
//! matches that exactly; the libRIST KAT is reproduced byte-for-byte by the tests.
//! A legacy pre-0.2.16 unpadded k/u mode (`srp-compat=1`) is exposed via
//! [`Client::new_legacy`] / [`Server::new_legacy`] for interop with old peers, but
//! the default and required path is PAD-compliant.
//!
//! Deterministic in the host's hands: it never reads a clock, opens a socket, or
//! spawns a task. The only non-determinism is the per-handshake secret (the
//! client's `a` and the server's `b`), drawn from the OS CSPRNG at construction;
//! everything downstream is a pure function of the inputs. White-box tests inject
//! deterministic a/b (mirroring libRIST's `DEBUG_USE_EXAMPLE_CONSTANTS`) to
//! reproduce the KAT.

// Justification: bit/byte-length conversions for the bignum group are bounded by
// the 2048-bit modulus; error/panic docs are covered by the module prose, and the
// only `expect` is on the compile-time modulus constant (a test pins it).
#![allow(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::cast_possible_truncation
)]

use std::sync::OnceLock;

use num_bigint::BigUint;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// The SHA-256 digest length in bytes: the SRP hash output size and the size of
/// M1, M2, and the session key K.
pub const HASH_LEN: usize = 32;

/// Errors returned by the SRP layer. User-facing `Display` strings are prefixed
/// `"rist: srp: "`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SrpError {
    /// The group is invalid (non-positive modulus or generator).
    #[error("rist: srp: invalid group")]
    InvalidGroup,
    /// The salt was empty.
    #[error("rist: srp: empty salt")]
    InvalidSalt,
    /// The salt exceeded [`MAX_SALT_LEN`] bytes. The wire CHALLENGE salt length is a
    /// 16-bit field, so an unbounded salt would force ~64 KiB of hashing per
    /// handshake (the salt feeds `x`, `M1`, and the session key); this caps the
    /// attacker-controllable work far above any legitimate salt.
    #[error("rist: srp: salt too long")]
    SaltTooLong,
    /// The verifier was empty or congruent to zero modulo N.
    #[error("rist: srp: invalid verifier")]
    InvalidVerifier,
    /// A peer-supplied public value was malformed (empty, longer than len(N), or
    /// congruent to zero modulo N), or the derived scrambling parameter u was zero
    /// — the SRP-6a safety aborts (RFC 5054 §2.6).
    #[error("rist: srp: bad SRP parameter")]
    BadParameter,
    /// The OS CSPRNG was unavailable while generating the per-handshake secret.
    #[error("rist: srp: CSPRNG read failed")]
    Csprng,
}

/// The 2048-bit RFC 5054 Appendix A modulus, libRIST's `NG_DEFAULT` (the second
/// `{n_hex, g_hex}` entry). g = 2.
const DEFAULT_N_HEX: &[u8] = b"AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050\
A37329CBB4A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50\
E8083969EDB767B0CF6095179A163AB3661A05FBD5FAAAE82918A9962F0B93B8\
55F97993EC975EEAA80D740ADBF4FF747359D041D5C33EA71D281E446B14773B\
CA97B43A23FB801676BD207A436C6481F1D2B9078717461A5B9D32E688F87748\
544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6\
AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB6\
94B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73";

/// The 2048-bit modulus, parsed once from [`DEFAULT_N_HEX`]. Parsing at first use
/// rather than per call keeps [`default_group`] free of a fallible parse and the
/// "no panics in library code" rule intact (the constant is compile-time, pinned
/// by a test).
fn default_n() -> &'static BigUint {
    static N: OnceLock<BigUint> = OnceLock::new();
    N.get_or_init(|| {
        BigUint::parse_bytes(DEFAULT_N_HEX, 16).expect("the 2048-bit RFC 5054 modulus is valid hex")
    })
}

/// Returns SHA-256 over the concatenation of `parts` — the SRP hash (libRIST's
/// `librist_crypto_srp_hash`). The [`eap`](crate::eap) layer hashes the same way
/// over message transcripts.
#[must_use]
pub fn hash(parts: &[&[u8]]) -> [u8; HASH_LEN] {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

/// The big-endian bytes of `x` at its natural minimal length (no leading zero
/// bytes), matching libRIST's `BIGNUM_GET_BINARY_SIZE` export. Zero yields an
/// empty slice (as mbedtls/nettle export zero as zero bytes).
fn minimal_bytes(x: &BigUint) -> Vec<u8> {
    if x.bits() == 0 {
        Vec::new()
    } else {
        x.to_bytes_be()
    }
}

/// Whether `x` is congruent to zero modulo `n`.
fn is_zero_mod(x: &BigUint, n: &BigUint) -> bool {
    (x % n).bits() == 0
}

/// The largest salt this package accepts. A real SRP salt is a small random nonce
/// (libRIST uses 32 bytes, bounded at 64); 1024 bytes is far above any legitimate
/// salt yet rejects an absurdly long, attacker-supplied one. Enforced by
/// [`make_verifier`], [`Client::new`], and [`Server::new`].
pub const MAX_SALT_LEN: usize = 1024;

/// Enforces the shared salt bounds: non-empty and at most [`MAX_SALT_LEN`] bytes.
fn validate_salt(salt: &[u8]) -> Result<(), SrpError> {
    if salt.is_empty() {
        return Err(SrpError::InvalidSalt);
    }
    if salt.len() > MAX_SALT_LEN {
        return Err(SrpError::SaltTooLong);
    }
    Ok(())
}

/// An SRP-6a group: a safe-prime modulus N and a generator g. The 2048-bit RFC
/// 5054 Appendix A group returned by [`default_group`] is libRIST's
/// `LIBRIST_SRP_NG_DEFAULT`.
#[derive(Debug, Clone)]
pub struct Group {
    /// The group modulus (a safe prime).
    n: BigUint,
    /// The group generator (2 for the default group).
    g: BigUint,
    /// len(N) in bytes, cached for PAD and export.
    length: usize,
}

/// Returns the 2048-bit RFC 5054 Appendix A group with g = 2 (libRIST's
/// `LIBRIST_SRP_NG_DEFAULT`).
#[must_use]
pub fn default_group() -> Group {
    Group::new(default_n().clone(), BigUint::from(2u32))
}

impl Group {
    /// Builds a group from N and g, caching len(N).
    fn new(n: BigUint, g: BigUint) -> Group {
        let length = n.bits().div_ceil(8) as usize;
        Group { n, g, length }
    }

    /// The byte length of N (the PAD target and the size of an exported A or B).
    #[must_use]
    pub fn length(&self) -> usize {
        self.length
    }

    /// Whether the group has a positive modulus and generator.
    fn valid(&self) -> bool {
        self.n.bits() > 0 && self.g.bits() > 0
    }

    /// The big-endian bytes of `x` left-zero-padded to len(N) bytes (RFC 5054
    /// PAD(x)). Used for the operands of k and u and to export A and B.
    fn pad(&self, x: &BigUint) -> Vec<u8> {
        let mb = minimal_bytes(x);
        let mut buf = vec![0u8; self.length];
        let start = self.length - mb.len();
        buf[start..].copy_from_slice(&mb);
        buf
    }

    /// `H(PAD(a) | PAD(b))` — the PAD-compliant hash for k and u.
    fn hash_padded(&self, a: &BigUint, b: &BigUint) -> [u8; HASH_LEN] {
        hash(&[&self.pad(a), &self.pad(b)])
    }

    /// `H(min(a) | min(b))` — the legacy pre-0.2.16 unpadded k/u hash.
    fn hash_unpadded(a: &BigUint, b: &BigUint) -> [u8; HASH_LEN] {
        hash(&[&minimal_bytes(a), &minimal_bytes(b)])
    }

    /// The SRP-6a multiplier k: `H(PAD(N)|PAD(g))`, or legacy unpadded `H(N|g)`.
    fn k_value(&self, legacy_pad: bool) -> BigUint {
        let d = if legacy_pad {
            Self::hash_unpadded(&self.n, &self.g)
        } else {
            self.hash_padded(&self.n, &self.g)
        };
        BigUint::from_bytes_be(&d)
    }

    /// The SRP-6a scrambling parameter u: `H(PAD(A)|PAD(B))`, or legacy `H(A|B)`.
    fn u_value(&self, a: &BigUint, b: &BigUint, legacy_pad: bool) -> BigUint {
        let d = if legacy_pad {
            Self::hash_unpadded(a, b)
        } else {
            self.hash_padded(a, b)
        };
        BigUint::from_bytes_be(&d)
    }

    /// `M1 = H( (H(N) XOR H(g)) | H(I) | salt | A | B | K )`, all of N,g,salt,A,B
    /// at minimal big-endian length (only k and u use PAD). The salt is
    /// canonicalized to minimal length.
    fn calc_m1(
        &self,
        username: &str,
        salt: &[u8],
        a: &BigUint,
        b: &BigUint,
        key: &[u8; HASH_LEN],
    ) -> [u8; HASH_LEN] {
        let h_n = hash(&[&minimal_bytes(&self.n)]);
        let h_g = hash(&[&minimal_bytes(&self.g)]);
        let mut xored = [0u8; HASH_LEN];
        for i in 0..HASH_LEN {
            xored[i] = h_n[i] ^ h_g[i];
        }
        let h_i = hash(&[username.as_bytes()]);
        hash(&[
            &xored,
            &h_i,
            &canon_salt(salt),
            &minimal_bytes(a),
            &minimal_bytes(b),
            key,
        ])
    }
}

/// `canonSalt`: strips leading zero bytes from the salt, matching libRIST, which
/// holds the salt as a BIGNUM and re-exports it at minimal big-endian length
/// wherever it is hashed (in calc_x and calculate_m). The wire salt keeps its
/// leading zeros; the HASHED form must not, or x/v/M1/K diverge from a libRIST
/// peer for any salt whose first byte is 0x00.
fn canon_salt(salt: &[u8]) -> Vec<u8> {
    minimal_bytes(&BigUint::from_bytes_be(salt))
}

/// `x = H( PAD-stripped salt | H( username | ":" | password ) )` (libRIST's
/// `calc_x`). The salt is hashed at its minimal big-endian length; the inner hash
/// `H("user:pass")` is unpadded.
fn calc_x(salt: &[u8], username: &str, password: &str) -> BigUint {
    let inner = hash(&[username.as_bytes(), b":", password.as_bytes()]);
    let outer = hash(&[&canon_salt(salt), &inner]);
    BigUint::from_bytes_be(&outer)
}

/// `K = H(S)` with S exported at its natural minimal length.
fn session_key(s: &BigUint) -> [u8; HASH_LEN] {
    hash(&[&minimal_bytes(s)])
}

/// `M2 = H( A | M1 | K )`, with A at minimal big-endian length.
fn calc_m2(a: &BigUint, m1: &[u8; HASH_LEN], key: &[u8; HASH_LEN]) -> [u8; HASH_LEN] {
    hash(&[&minimal_bytes(a), m1, key])
}

/// Returns the SRP-6a verifier `v = g^x mod N` for the credentials and salt, at
/// its natural minimal big-endian length (matching libRIST's
/// `create_verifier`). A nil-ish or invalid group, or empty salt, yields `None`.
#[must_use]
pub fn make_verifier(g: &Group, username: &str, password: &str, salt: &[u8]) -> Option<Vec<u8>> {
    if !g.valid() || validate_salt(salt).is_err() {
        return None;
    }
    let x = calc_x(salt, username, password);
    let v = g.g.modpow(&x, &g.n);
    Some(minimal_bytes(&v))
}

/// Draws a per-handshake secret uniformly in [0, N) from the OS CSPRNG (rejection
/// sampling, matching libRIST's `BIGNUM_RANDOM`).
fn read_secret(n: &BigUint) -> Result<BigUint, SrpError> {
    let bits = n.bits();
    let nbytes = bits.div_ceil(8) as usize;
    let excess = (nbytes as u64 * 8 - bits) as u32; // high bits to clear
    for _ in 0..256 {
        let mut buf = vec![0u8; nbytes];
        getrandom::fill(&mut buf).map_err(|_| SrpError::Csprng)?;
        if excess > 0 {
            buf[0] &= 0xFFu8 >> excess;
        }
        let v = BigUint::from_bytes_be(&buf);
        if &v < n {
            return Ok(v);
        }
    }
    Err(SrpError::Csprng)
}

/// An SRP-6a authenticatee. Holds the group, salt, the per-handshake secret a and
/// public A, and — after [`Client::compute_key`] — the session key K and the
/// proof M1. Single-use; not safe for concurrent use.
#[derive(Debug)]
pub struct Client {
    group: Group,
    salt: Vec<u8>,
    a: BigUint,
    pub_a: BigUint,
    legacy_pad: bool,
    computed: bool,
    key: [u8; HASH_LEN],
    m1: [u8; HASH_LEN],
}

impl Client {
    /// Creates an SRP-6a client for the group and salt, drawing a random secret a
    /// and computing A = g^a mod N. Errors on an invalid group, empty salt, or a
    /// CSPRNG failure.
    pub fn new(g: &Group, salt: &[u8]) -> Result<Client, SrpError> {
        Self::new_inner(g, salt, false)
    }

    /// [`Client::new`] with the pre-0.2.16 unpadded k/u hashing (`srp-compat=1`).
    /// Use only to interoperate with old peers.
    pub fn new_legacy(g: &Group, salt: &[u8]) -> Result<Client, SrpError> {
        Self::new_inner(g, salt, true)
    }

    fn new_inner(g: &Group, salt: &[u8], legacy_pad: bool) -> Result<Client, SrpError> {
        if !g.valid() {
            return Err(SrpError::InvalidGroup);
        }
        validate_salt(salt)?;
        let a = read_secret(&g.n)?;
        let pub_a = g.g.modpow(&a, &g.n);
        Ok(Client {
            group: g.clone(),
            salt: salt.to_vec(),
            a,
            pub_a,
            legacy_pad,
            computed: false,
            key: [0u8; HASH_LEN],
            m1: [0u8; HASH_LEN],
        })
    }

    /// The client public value A = g^a mod N, big-endian and padded to len(N)
    /// bytes. (libRIST sends A at minimal length with a length field; the pad is
    /// value-preserving and interop-safe — the peer reconstructs the same bignum
    /// and u re-pads both operands.)
    #[must_use]
    pub fn a(&self) -> Vec<u8> {
        self.group.pad(&self.pub_a)
    }

    /// Processes the server public value B and derives x, u, the premaster secret
    /// S, the session key K = H(S), and the client proof M1. Returns
    /// [`SrpError::BadParameter`] if B is empty, longer than len(N), congruent to
    /// zero mod N, or if the derived u is zero (the SRP-6a safety aborts).
    pub fn compute_key(
        &mut self,
        server_b: &[u8],
        username: &str,
        password: &str,
    ) -> Result<(), SrpError> {
        let gr = &self.group;
        if server_b.is_empty() || server_b.len() > gr.length {
            return Err(SrpError::BadParameter);
        }
        let b_pub = BigUint::from_bytes_be(server_b);
        if is_zero_mod(&b_pub, &gr.n) {
            return Err(SrpError::BadParameter);
        }

        let u = gr.u_value(&self.pub_a, &b_pub, self.legacy_pad);
        if is_zero_mod(&u, &gr.n) {
            return Err(SrpError::BadParameter);
        }

        let k = gr.k_value(self.legacy_pad);
        let x = calc_x(&self.salt, username, password);

        // gx = g^x mod N (this is v).
        let gx = gr.g.modpow(&x, &gr.n);

        // base = (B - k*gx) mod N, in [0, N): compute with non-negative modular
        // arithmetic (b_mod + N - kgx is in (0, 2N) since both are reduced).
        let b_mod = &b_pub % &gr.n;
        let kgx = (&k * &gx) % &gr.n;
        let base = ((&b_mod + &gr.n) - &kgx) % &gr.n;

        // exp = a + u*x; S = base^exp mod N.
        let exp = &self.a + &u * &x;
        let s = base.modpow(&exp, &gr.n);

        self.key = session_key(&s);
        self.m1 = gr.calc_m1(username, &self.salt, &self.pub_a, &b_pub, &self.key);
        self.computed = true;
        Ok(())
    }

    /// The 32-byte client proof, valid only after [`Client::compute_key`]; `None`
    /// before that.
    #[must_use]
    pub fn m1(&self) -> Option<[u8; HASH_LEN]> {
        self.computed.then_some(self.m1)
    }

    /// Whether the server proof M2 matches `H(A | M1 | K)`, in constant time.
    /// `false` if [`Client::compute_key`] has not run or `m2` is not 32 bytes.
    #[must_use]
    pub fn verify_m2(&self, m2: &[u8]) -> bool {
        if !self.computed || m2.len() != HASH_LEN {
            return false;
        }
        let want = calc_m2(&self.pub_a, &self.m1, &self.key);
        want.ct_eq(m2).into()
    }

    /// The 32-byte shared session key K = H(S), valid only after
    /// [`Client::compute_key`]; `None` before that.
    #[must_use]
    pub fn session_key(&self) -> Option<[u8; HASH_LEN]> {
        self.computed.then_some(self.key)
    }
}

/// An SRP-6a authenticator. Holds the group, salt, verifier v, the per-handshake
/// secret b and public B, the client public A (after [`Server::handle_a`]), and —
/// after [`Server::verify_m1`] — the session key K and the proof M2. Single-use;
/// not safe for concurrent use.
#[derive(Debug)]
pub struct Server {
    group: Group,
    salt: Vec<u8>,
    v: BigUint,
    b: BigUint,
    pub_b: BigUint,
    pub_a: Option<BigUint>,
    legacy_pad: bool,
    verified: bool,
    key: [u8; HASH_LEN],
    m2: [u8; HASH_LEN],
}

impl Server {
    /// Creates an SRP-6a server for the group, verifier, and salt, drawing a random
    /// secret b and computing B = (k*v + g^b) mod N. Errors on an invalid group,
    /// empty salt, empty or zero-mod-N verifier, a CSPRNG failure, or a B that is
    /// congruent to zero mod N.
    pub fn new(g: &Group, verifier: &[u8], salt: &[u8]) -> Result<Server, SrpError> {
        Self::new_inner(g, verifier, salt, false)
    }

    /// [`Server::new`] with the pre-0.2.16 unpadded k/u hashing (`srp-compat=1`).
    pub fn new_legacy(g: &Group, verifier: &[u8], salt: &[u8]) -> Result<Server, SrpError> {
        Self::new_inner(g, verifier, salt, true)
    }

    fn new_inner(
        g: &Group,
        verifier: &[u8],
        salt: &[u8],
        legacy_pad: bool,
    ) -> Result<Server, SrpError> {
        if !g.valid() {
            return Err(SrpError::InvalidGroup);
        }
        validate_salt(salt)?;
        if verifier.is_empty() {
            return Err(SrpError::InvalidVerifier);
        }
        let v = BigUint::from_bytes_be(verifier);
        if is_zero_mod(&v, &g.n) {
            return Err(SrpError::InvalidVerifier);
        }
        let b = read_secret(&g.n)?;
        let mut s = Server {
            group: g.clone(),
            salt: salt.to_vec(),
            v,
            b,
            pub_b: BigUint::ZERO,
            pub_a: None,
            legacy_pad,
            verified: false,
            key: [0u8; HASH_LEN],
            m2: [0u8; HASH_LEN],
        };
        s.compute_b()?;
        Ok(s)
    }

    /// Sets B = (k*v + g^b) mod N, rejecting B == 0 mod N.
    fn compute_b(&mut self) -> Result<(), SrpError> {
        let gr = &self.group;
        let k = gr.k_value(self.legacy_pad);
        let gb = gr.g.modpow(&self.b, &gr.n);
        let kv = &k * &self.v;
        self.pub_b = (&kv + &gb) % &gr.n;
        if self.pub_b.bits() == 0 {
            return Err(SrpError::BadParameter);
        }
        Ok(())
    }

    /// The server public value B = (k*v + g^b) mod N, big-endian and padded to
    /// len(N) bytes.
    #[must_use]
    pub fn b(&self) -> Vec<u8> {
        self.group.pad(&self.pub_b)
    }

    /// Stores and validates the client public value A. Returns
    /// [`SrpError::BadParameter`] if A is empty, longer than len(N), or congruent
    /// to zero modulo N (the SRP-6a safety abort).
    pub fn handle_a(&mut self, client_a: &[u8]) -> Result<(), SrpError> {
        let gr = &self.group;
        if client_a.is_empty() || client_a.len() > gr.length {
            return Err(SrpError::BadParameter);
        }
        let a = BigUint::from_bytes_be(client_a);
        if is_zero_mod(&a, &gr.n) {
            return Err(SrpError::BadParameter);
        }
        self.pub_a = Some(a);
        Ok(())
    }

    /// Derives u, the premaster secret S = (A * v^u)^b mod N, the session key
    /// K = H(S), and the server-side M1; compares M1 against the client's proof in
    /// constant time; on a match computes M2 and returns `true`. `false` if
    /// [`Server::handle_a`] has not run, `m1` is not 32 bytes, u is zero, or the
    /// proof does not match.
    #[must_use]
    pub fn verify_m1(&mut self, username: &str, m1: &[u8]) -> bool {
        let Some(pub_a) = self.pub_a.clone() else {
            return false;
        };
        if m1.len() != HASH_LEN {
            return false;
        }
        let gr = &self.group;
        let u = gr.u_value(&pub_a, &self.pub_b, self.legacy_pad);
        if is_zero_mod(&u, &gr.n) {
            return false;
        }

        // S = (A * (v^u mod N))^b mod N.
        let vu = self.v.modpow(&u, &gr.n);
        let avu = (&pub_a * &vu) % &gr.n;
        let s_shared = avu.modpow(&self.b, &gr.n);

        self.key = session_key(&s_shared);
        let want = gr.calc_m1(username, &self.salt, &pub_a, &self.pub_b, &self.key);

        if !bool::from(want.ct_eq(m1)) {
            return false;
        }
        self.m2 = calc_m2(&pub_a, &want, &self.key);
        self.verified = true;
        true
    }

    /// The 32-byte server proof, valid only after [`Server::verify_m1`] succeeded;
    /// `None` before that.
    #[must_use]
    pub fn m2(&self) -> Option<[u8; HASH_LEN]> {
        self.verified.then_some(self.m2)
    }

    /// The 32-byte shared session key K = H(S), valid only after
    /// [`Server::verify_m1`] succeeded; `None` before that.
    #[must_use]
    pub fn session_key(&self) -> Option<[u8; HASH_LEN]> {
        self.verified.then_some(self.key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hx(s: &str) -> Vec<u8> {
        let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn big(hexs: &str) -> BigUint {
        BigUint::from_bytes_be(&hx(hexs))
    }

    // libRIST KAT (PAD-compliant, DEBUG_USE_EXAMPLE_CONSTANTS=1) on NG_DEFAULT.
    // username="rist", password="mainprofile".
    const KAT_SALT: &str = "72F9D5383B7EB7599FB63028F47475B60A55F313D40E0BE023E026C97C0A2C32";
    const KAT_A_SECRET: &str = "138AB4045633AD14961CB1AD0720B1989104151C0708794491113302CCCC27D5";
    const KAT_B_SECRET: &str = "ED0D58FF861A1FC75A0829BEA5F1392D2B13AB2B05CBCD6ED1E71AAAD761E856";
    const KAT_INNER: &str = "8427F6E0E69DC9B99DFE1052DDAF7E50D4FEA316C63C6AD23FE197C9C1DA2AF1";
    const KAT_VERIFIER: &str = "16B380409C1D6A43A96B42DD0FAC130D54A1932205F51F26AC13FB5332331C7B\
66A313ED969E24CB2AC5447C04FFC6565BC9FEA75A79D865FF7BB0DD65C62065\
EAAE7A27048F3B4C1FC0502C622FFE5B196400AD9470DB9F9DFB55CC4710081F\
DAEE3B63B69C15D43E189EF3E6E1C1FB1A9268F8E6DCDF16E1726585B883960E\
E09B318D3DD9E1C93D1B3EC98C148C00927028C1ED14D342B72811B962C233B7\
1096BDD2EE505539DDC04ED03FDAA69926417E86016406480F8EB41317FF3D5E\
3B4735C76BCE67333B1F1E5E6A467E7E45A70D66EE1FC474A179697C5690AC1A\
525D2ADD050CC9D9824232AEC6FD8206CBEA5144AA2AC31B9865CEACF3BA2A72";
    const KAT_A: &str = "545DD89CD403BA71172016F156A537A2D369B8551004AB521CC62D76B71BD278\
E687294A3D265B96393A582D8823E4BB3A7960F641D7A01DD7E13C982F06B052\
2EC147B1451C63F099FD08A9D5A6FD5CA73907B13E0672DEFAEF976BEA78E8F4\
C3E60E85B86FE68F84658D3A792D90F2FB834E657C5F1E6AAA532A3D3F4F2D74\
7D8F3D0C0CC8F999773ED4FFE159A8B8ACB2761C6C523C68BC866EE464091B6F\
86720EFFB02824AC1FB31675B7F07DD2292B937C9EDE73C2420A3204CA0BBD51\
9274B5D35771019265BE5E213C9634540A0D56EA94BA306AD1965EFF986AF896\
3ECE5E30E057517A0D0082205E1086520039A03D60D739FCD7BB335CBB3AF39A";
    const KAT_B: &str = "461F82DB9BBD64DD580800C38B854437F0AE29CA14B0AD4A03797CA4EB6A27CD\
3C1B90E06E1C539A5FFE61E905497E78E8433F5303BEC8ECB23008DA86EBFB1B\
1B2FED35129BBC2ED346A810CC2A0AB20E44E2B94E048C9F9A17ABD87651CD1F\
2642873E487E0DDB3987D68F1B831CA8598AB88B377FAA7B06DCFE0E83A6D97F\
FB50D429285518209A4AEFA66F5A2BA499918209362CF0907EDC9E265156FCB8\
A945027F4DCDE178B8169D796187B79AA133E3BE02AF81C6AEC0B675D5F9E25E\
78CE00D5A0FE3BADC7106A2DAFB078BF30EF8677DD4D1EE60B50B110446C576C\
DDA3FA930C837938FE4AC4CF2F28185A2DD87F9524F1D5746E93D9A8FFF53626";
    const KAT_M1: &str = "2EE41138D2C447E7469EB589B89CF96FAF869B55DD684897DAB173056F1D8F90";
    const KAT_M2: &str = "28E0412112CD83DDC97B3395AB0D27F5C0A1EB4FA89205CD505957F53988A639";
    const KAT_K: &str = "0E7822B56248FFE74D0A4639BD7194E848DF0E590A5D9AD414021EE7FAB360A8";
    const USER: &str = "rist";
    const PASS: &str = "mainprofile";

    #[test]
    fn hash_inner() {
        assert_eq!(hash(&[b"rist:mainprofile"]), hx(KAT_INNER).as_slice());
        assert_eq!(
            hash(&[b"rist", b":", b"mainprofile"]),
            hx(KAT_INNER).as_slice()
        );
        // Empty input is SHA-256 of the empty string.
        assert_eq!(hash(&[]).to_vec(), {
            let mut h = Sha256::new();
            h.update(b"");
            h.finalize().to_vec()
        });
    }

    #[test]
    fn default_group_is_2048_bit() {
        let g = default_group();
        assert_eq!(g.n, *default_n());
        assert_eq!(g.g, BigUint::from(2u32));
        assert_eq!(g.length, 256);
        assert_eq!(g.n.bits(), 2048);
    }

    #[test]
    fn verifier_kat() {
        let g = default_group();
        let salt = hx(KAT_SALT);
        let v = make_verifier(&g, USER, PASS, &salt).unwrap();
        assert_eq!(v, hx(KAT_VERIFIER));
        assert_eq!(v.len(), 256);
    }

    #[test]
    fn client_server_kat() {
        let g = default_group();
        let salt = hx(KAT_SALT);
        let v = make_verifier(&g, USER, PASS, &salt).unwrap();

        let mut c = Client::new(&g, &salt).unwrap();
        // Inject the deterministic client secret a (white-box KAT).
        c.a = big(KAT_A_SECRET);
        c.pub_a = g.g.modpow(&c.a, &g.n);

        let mut s = Server::new(&g, &v, &salt).unwrap();
        s.b = big(KAT_B_SECRET);
        s.compute_b().unwrap();

        assert_eq!(c.a(), hx(KAT_A), "A");
        assert_eq!(s.b(), hx(KAT_B), "B");

        c.compute_key(&s.b(), USER, PASS).unwrap();
        assert_eq!(c.m1().unwrap().to_vec(), hx(KAT_M1), "M1");

        s.handle_a(&c.a()).unwrap();
        assert!(s.verify_m1(USER, &c.m1().unwrap()), "server VerifyM1");
        assert_eq!(s.m2().unwrap().to_vec(), hx(KAT_M2), "M2");

        assert!(c.verify_m2(&s.m2().unwrap()), "client VerifyM2");

        let ck = c.session_key().unwrap();
        assert_eq!(ck, s.session_key().unwrap(), "session keys agree");
        assert_eq!(ck.to_vec(), hx(KAT_K), "K");
    }

    #[test]
    fn round_trip_random() {
        let g = default_group();
        for i in 0..8 {
            let salt = {
                let mut s = [0u8; 32];
                getrandom::fill(&mut s).unwrap();
                s
            };
            let (user, pass) = ("operator", "s3cr3t-pass-w0rd");
            let v = make_verifier(&g, user, pass, &salt).unwrap();
            let mut c = Client::new(&g, &salt).unwrap();
            let mut s = Server::new(&g, &v, &salt).unwrap();
            s.handle_a(&c.a()).unwrap();
            c.compute_key(&s.b(), user, pass).unwrap();
            assert!(s.verify_m1(user, &c.m1().unwrap()), "iter {i} VerifyM1");
            assert!(c.verify_m2(&s.m2().unwrap()), "iter {i} VerifyM2");
            assert_eq!(c.session_key(), s.session_key(), "iter {i} keys");
        }
    }

    #[test]
    fn legacy_round_trip() {
        let g = default_group();
        let mut salt = [0u8; 32];
        getrandom::fill(&mut salt).unwrap();
        let v = make_verifier(&g, USER, PASS, &salt).unwrap();
        let mut c = Client::new_legacy(&g, &salt).unwrap();
        let mut s = Server::new_legacy(&g, &v, &salt).unwrap();
        s.handle_a(&c.a()).unwrap();
        c.compute_key(&s.b(), USER, PASS).unwrap();
        assert!(s.verify_m1(USER, &c.m1().unwrap()));
        assert!(c.verify_m2(&s.m2().unwrap()));
        assert_eq!(c.session_key(), s.session_key());
    }

    #[test]
    fn mode_mismatch_fails_at_m1() {
        let g = default_group();
        let mut salt = [0u8; 32];
        getrandom::fill(&mut salt).unwrap();
        let v = make_verifier(&g, USER, PASS, &salt).unwrap();
        for (client_legacy, server_legacy) in [(true, false), (false, true)] {
            let mut c = if client_legacy {
                Client::new_legacy(&g, &salt)
            } else {
                Client::new(&g, &salt)
            }
            .unwrap();
            let mut s = if server_legacy {
                Server::new_legacy(&g, &v, &salt)
            } else {
                Server::new(&g, &v, &salt)
            }
            .unwrap();
            s.handle_a(&c.a()).unwrap();
            c.compute_key(&s.b(), USER, PASS).unwrap();
            assert!(
                !s.verify_m1(USER, &c.m1().unwrap()),
                "mode mismatch must reject (client_legacy={client_legacy})"
            );
        }
    }

    #[test]
    fn wrong_password_rejected() {
        let g = default_group();
        let salt = hx(KAT_SALT);
        let v = make_verifier(&g, USER, PASS, &salt).unwrap();
        let mut c = Client::new(&g, &salt).unwrap();
        let mut s = Server::new(&g, &v, &salt).unwrap();
        s.handle_a(&c.a()).unwrap();
        c.compute_key(&s.b(), USER, "wrong-password").unwrap();
        assert!(!s.verify_m1(USER, &c.m1().unwrap()));
        assert!(s.m2().is_none());
        assert!(s.session_key().is_none());
    }

    #[test]
    fn safety_aborts() {
        let g = default_group();
        let salt = hx(KAT_SALT);
        let v = make_verifier(&g, USER, PASS, &salt).unwrap();
        let n_bytes = {
            let mut b = vec![0u8; g.length];
            let nb = g.n.to_bytes_be();
            b[g.length - nb.len()..].copy_from_slice(&nb);
            b
        };

        // Server rejects A == 0 mod N, A == 0, empty, oversize.
        let mut s = Server::new(&g, &v, &salt).unwrap();
        assert_eq!(s.handle_a(&n_bytes), Err(SrpError::BadParameter));
        assert_eq!(
            s.handle_a(&vec![0u8; g.length]),
            Err(SrpError::BadParameter)
        );
        assert_eq!(s.handle_a(&[]), Err(SrpError::BadParameter));
        assert_eq!(
            s.handle_a(&vec![0u8; g.length + 1]),
            Err(SrpError::BadParameter)
        );

        // Client rejects B == 0 mod N, B == 0, empty, oversize.
        let mut c = Client::new(&g, &salt).unwrap();
        assert_eq!(
            c.compute_key(&n_bytes, USER, PASS),
            Err(SrpError::BadParameter)
        );
        assert_eq!(
            c.compute_key(&vec![0u8; g.length], USER, PASS),
            Err(SrpError::BadParameter)
        );
        assert_eq!(c.compute_key(&[], USER, PASS), Err(SrpError::BadParameter));
        assert_eq!(
            c.compute_key(&vec![0u8; g.length + 1], USER, PASS),
            Err(SrpError::BadParameter)
        );

        // Server rejects verifier v == 0 / empty.
        assert_eq!(
            Server::new(&g, &vec![0u8; g.length], &salt).err(),
            Some(SrpError::InvalidVerifier)
        );
        assert_eq!(
            Server::new(&g, &[], &salt).err(),
            Some(SrpError::InvalidVerifier)
        );
    }

    #[test]
    fn corrupt_proofs_rejected() {
        let g = default_group();
        let salt = hx(KAT_SALT);
        let v = make_verifier(&g, USER, PASS, &salt).unwrap();
        let mut s = Server::new(&g, &v, &salt).unwrap();
        let mut c = Client::new(&g, &salt).unwrap();
        s.handle_a(&c.a()).unwrap();
        c.compute_key(&s.b(), USER, PASS).unwrap();

        let mut bad_m1 = c.m1().unwrap();
        bad_m1[0] ^= 0xFF;
        assert!(!s.verify_m1(USER, &bad_m1), "corrupt M1");
        assert!(!s.verify_m1(USER, &bad_m1[..16]), "short M1");

        assert!(s.verify_m1(USER, &c.m1().unwrap()));
        let mut bad_m2 = s.m2().unwrap();
        bad_m2[31] ^= 0x01;
        assert!(!c.verify_m2(&bad_m2), "corrupt M2");
        assert!(!c.verify_m2(&bad_m2[..16]), "short M2");
    }

    #[test]
    fn accessors_before_ready() {
        let g = default_group();
        let salt = hx(KAT_SALT);
        let v = make_verifier(&g, USER, PASS, &salt).unwrap();
        let c = Client::new(&g, &salt).unwrap();
        assert!(c.m1().is_none());
        assert!(c.session_key().is_none());
        assert!(!c.verify_m2(&[0u8; 32]));
        let mut s = Server::new(&g, &v, &salt).unwrap();
        assert!(s.m2().is_none());
        assert!(s.session_key().is_none());
        assert!(!s.verify_m1(USER, &[0u8; 32]), "VerifyM1 before HandleA");
    }

    #[test]
    fn constructor_validation_and_export_sizes() {
        let g = default_group();
        let salt = hx(KAT_SALT);
        let bad = Group::new(BigUint::ZERO, BigUint::from(2u32));
        assert_eq!(Client::new(&bad, &salt).err(), Some(SrpError::InvalidGroup));
        assert_eq!(Client::new(&g, &[]).err(), Some(SrpError::InvalidSalt));
        let v = make_verifier(&g, USER, PASS, &salt).unwrap();
        assert_eq!(
            Server::new(&bad, &v, &salt).err(),
            Some(SrpError::InvalidGroup)
        );
        assert_eq!(Server::new(&g, &v, &[]).err(), Some(SrpError::InvalidSalt));
        assert!(make_verifier(&g, USER, PASS, &[]).is_none());
        assert!(make_verifier(&bad, USER, PASS, &salt).is_none());

        // A salt longer than MAX_SALT_LEN is rejected (a hashing-work bound); a
        // max-length salt is accepted.
        let huge = vec![1u8; MAX_SALT_LEN + 1];
        assert_eq!(Client::new(&g, &huge).err(), Some(SrpError::SaltTooLong));
        assert_eq!(
            Server::new(&g, &v, &huge).err(),
            Some(SrpError::SaltTooLong)
        );
        assert!(make_verifier(&g, USER, PASS, &huge).is_none());
        assert!(Client::new(&g, &vec![1u8; MAX_SALT_LEN]).is_ok());

        // A and B are always padded to len(N).
        let c = Client::new(&g, &salt).unwrap();
        assert_eq!(c.a().len(), g.length);
        let s = Server::new(&g, &v, &salt).unwrap();
        assert_eq!(s.b().len(), g.length);
    }
}
