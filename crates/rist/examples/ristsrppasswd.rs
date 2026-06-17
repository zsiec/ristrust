//! `ristsrppasswd` — generate an EAP-SRP verifier line for the RIST Main profile,
//! in the same format as libRIST's `ristsrppasswd` tool:
//!
//! ```text
//! username:base64(verifier):base64(salt):3:1
//! ```
//!
//! The trailing fields are the SRP hash version (3 = RFC 5054 PAD-compliant, EAPOL
//! v3) and the correct-hashing flag (1). The line is what an EAP-SRP authenticator's
//! verifier lookup consumes to authenticate a user without storing the plaintext
//! password. The verifier is `v = g^x mod N` with `x = H(salt | H(username ":"
//! password))`; minimal big-endian bytes, matching libRIST, so the files are
//! interchangeable.
//!
//! ```text
//! ristsrppasswd <username> <password> [salt-hex]
//! ```
//!
//! A 32-byte random salt is generated unless an explicit hex salt is given (the
//! explicit form is deterministic, for testing / reproducible provisioning).

use rist_codec::srp::{default_group, make_verifier};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 && args.len() != 4 {
        let prog = args.first().map_or("ristsrppasswd", String::as_str);
        eprintln!("usage: {prog} <username> <password> [salt-hex]");
        std::process::exit(2);
    }
    let (username, password) = (&args[1], &args[2]);

    // libRIST uses a 32-byte random salt; an explicit hex salt makes it deterministic.
    let salt = if let Some(hexstr) = args.get(3) {
        match decode_hex(hexstr) {
            Some(s) if !s.is_empty() => s,
            _ => {
                eprintln!("ristsrppasswd: invalid salt hex");
                std::process::exit(2);
            }
        }
    } else {
        let mut s = vec![0u8; 32];
        if getrandom::fill(&mut s).is_err() {
            eprintln!("ristsrppasswd: CSPRNG unavailable");
            std::process::exit(1);
        }
        s
    };

    let Some(verifier) = make_verifier(&default_group(), username, password, &salt) else {
        eprintln!("ristsrppasswd: could not create verifier (empty credentials?)");
        std::process::exit(1);
    };
    println!("{username}:{}:{}:3:1", base64(&verifier), base64(&salt));
}

/// Standard base64 (RFC 4648) encoder — inline to avoid a dependency for one use.
fn base64(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = u32::from(chunk[0]);
        let b1 = u32::from(chunk.get(1).copied().unwrap_or(0));
        let b2 = u32::from(chunk.get(2).copied().unwrap_or(0));
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[((n >> 18) & 63) as usize] as char);
        out.push(ALPHABET[((n >> 12) & 63) as usize] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[((n >> 6) & 63) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[(n & 63) as usize] as char
        } else {
            '='
        });
    }
    out
}

/// Decodes an even-length hex string, or `None` on any invalid character.
fn decode_hex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}
