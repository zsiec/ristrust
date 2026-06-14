# NOTICE

ristrust — a pure-Rust implementation of the RIST protocol (VSF TR-06 family).
Copyright (c) 2026 Thomas Symborski. Licensed under the [MIT License](LICENSE).

This file records attributions for third-party code and algorithms ported into
this repository. (Pure-Rust crate dependencies — RustCrypto, tokio, bytes, etc. —
are used unmodified through Cargo and are not reproduced here; their licenses are
permissive and are vetted by `cargo deny`.)

Attributions below land as the corresponding modules are implemented; the ports
mirror those in the sibling Go project `ristgo` and carry the same provenance.

## RTP / RTCP (pion)

`rist-codec::rtp` will port (trimmed and adapted) the RTP `Header`/`Packet`
marshalling logic from [pion/rtp](https://github.com/pion/rtp), and
`rist-codec::rtcp` the Generic NACK FCI packing from [pion/rtcp]'s
`TransportLayerNack` (RFC 4585 Generic NACK, RTCP PT=205/FMT=1). pion is licensed
under the MIT License, Copyright (c) The Pion community (<https://pion.ly>):

> MIT License
>
> Copyright (c) The Pion community <https://pion.ly>
>
> Permission is hereby granted, free of charge, to any person obtaining a copy
> of this software and associated documentation files (the "Software"), to deal
> in the Software without restriction, including without limitation the rights
> to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
> copies of the Software, and to permit persons to whom the Software is furnished
> to do so, subject to the following conditions:
>
> The above copyright notice and this permission notice shall be included in all
> copies or substantial portions of the Software.
>
> THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
> IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
> FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
> AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
> LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
> OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
> SOFTWARE.

## LZ4 (lz4/lz4)

`rist-codec::lpc` will be a pure-Rust reimplementation of the LZ4 *block* format
compressor/decompressor (no C copied), ported from the published LZ4 block-format
specification and the algorithm of the reference implementation,
[lz4/lz4](https://github.com/lz4/lz4) (Yann Collet). It is used by the RIST
Advanced Profile for payload compression (LPC=1 = LZ4) and must decode libRIST's
vendored-LZ4 blocks. lz4 is licensed under the BSD 2-Clause License, Copyright
(C) 2011-2023, Yann Collet:

> LZ4 - Fast LZ compression algorithm
> Copyright (C) 2011-2023, Yann Collet.
>
> BSD 2-Clause License (http://www.opensource.org/licenses/bsd-license.php)
>
> Redistribution and use in source and binary forms, with or without
> modification, are permitted provided that the following conditions are met:
>
>     * Redistributions of source code must retain the above copyright notice,
>       this list of conditions and the following disclaimer.
>     * Redistributions in binary form must reproduce the above copyright
>       notice, this list of conditions and the following disclaimer in the
>       documentation and/or other materials provided with the distribution.
>
> THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
> AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
> IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
> ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
> LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
> CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
> SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
> INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
> CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
> ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
> POSSIBILITY OF SUCH DAMAGE.

## Future attributions

Additional ports planned for later phases will be attributed here when the code
arrives.
