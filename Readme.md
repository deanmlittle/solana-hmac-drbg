# solana-hmac-drbg
A simple implementation of HMAC DRBG (Deterministic Random Bit Generator) for Solana

DRBG is used in [RFC6979](https://datatracker.ietf.org/doc/html/rfc6979) for deterministic nonce generation.

Please note that DRBG alone is not the full implementation of RFC6979, as a valid nonce would also need to clamped within the finite field of the curve you are using for ECDSA. For the full implementation of RFC6979, check out [solana-rfc6979](https://github.com/deanmlittle/solana-rfc6979).

### Usage

```rs
let privkey: [u8;32] = [0xc9, 0xaf, 0xa9, 0xd8, 0x45, 0xba, 0x75, 0x16, 0x6b, 0x5c, 0x21, 0x57, 0x67, 0xb1, 0xd6, 0x93, 0x4e, 0x50, 0xc3, 0xdb, 0x36, 0xe8, 0x9b, 0x12, 0x7b, 0x8a, 0x62, 0x2b, 0x12, 0x0f, 0x67, 0x21];
let message_hash: [u8;32] = [0xaf, 0x2b, 0xdb, 0xe1, 0xaa, 0x9b, 0x6e, 0xc1, 0xe2, 0xad, 0xe1, 0xd6, 0x94, 0xf4, 0x1f, 0xc7, 0x1a, 0x83, 0x1d, 0x02, 0x68, 0xe9, 0x89, 0x15, 0x62, 0x11, 0x3d, 0x8a, 0x62, 0xad, 0xd1, 0xbf];
let mut result = [0u8;32];
HmacDrbg::new(&privkey, &message_hash).fill_bytes(&mut result); // Fills in result with resulting [u8;32]
```