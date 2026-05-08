//! A more efficient, no_std HMAC-SHA-256 DRBG (Deterministic Random Bit
//! Generator) for the Solana SVM.
//!
//! Built on top of [`solana_hmac_sha256`], so on `target_os = "solana"`
//! every internal HMAC routes through the `sol_sha256` syscall. Off-Solana
//! it falls through to the `sha2` crate, so the same API works in host
//! code (tests, off-chain tooling).
//!
//! See [RFC 6979](https://datatracker.ietf.org/doc/html/rfc6979) for the
//! deterministic nonce construction this implements. DRBG alone is not the
//! full RFC 6979 — a valid nonce must also be clamped to the curve
//! subgroup; see [`solana-rfc6979`](https://github.com/blueshift-gg/solana-rfc6979).
#![no_std]

use solana_hmac_sha256::hmac_sha256;

const HASH_LENGTH: usize = 32;
const SEED_BUF_LEN: usize = HASH_LENGTH + 1 + HASH_LENGTH + HASH_LENGTH;

/// HMAC-SHA-256 deterministic random bit generator.
#[derive(Clone)]
pub struct HmacDrbg {
    k: [u8; HASH_LENGTH],
    v: [u8; HASH_LENGTH],
}

impl HmacDrbg {
    pub fn new(private_key: &[u8; HASH_LENGTH], message_hash: &[u8; HASH_LENGTH]) -> Self {
        let mut k: [u8; 32] = [0u8; HASH_LENGTH];
        let mut v = [1u8; HASH_LENGTH];

        let mut buf = [0u8; SEED_BUF_LEN];
        buf[HASH_LENGTH + 1..HASH_LENGTH + 1 + HASH_LENGTH].copy_from_slice(private_key);
        buf[HASH_LENGTH + 1 + HASH_LENGTH..].copy_from_slice(message_hash);

        for i in 0..=1u8 {
            buf[..HASH_LENGTH].copy_from_slice(&v);
            buf[HASH_LENGTH] = i;
            k = hmac_sha256(&k, &buf);
            v = hmac_sha256(&k, &v);
        }

        Self { k, v }
    }

    pub fn fill_bytes(&mut self, out: &mut [u8]) {
        for out_chunk in out.chunks_mut(HASH_LENGTH) {
            self.v = hmac_sha256(&self.k, &self.v);
            out_chunk.copy_from_slice(&self.v[..out_chunk.len()]);
        }

        let mut buf = [0u8; HASH_LENGTH + 1];
        buf[..HASH_LENGTH].copy_from_slice(&self.v);
        self.k = hmac_sha256(&self.k, &buf);
        self.v = hmac_sha256(&self.k, &self.v);
    }
}

#[cfg(test)]
mod tests {
    use crate::HmacDrbg;

    #[test]
    fn hmac_drbg_test() {
        let x: [u8; 32] = [
            0xc9, 0xaf, 0xa9, 0xd8, 0x45, 0xba, 0x75, 0x16, 0x6b, 0x5c, 0x21, 0x57, 0x67, 0xb1,
            0xd6, 0x93, 0x4e, 0x50, 0xc3, 0xdb, 0x36, 0xe8, 0x9b, 0x12, 0x7b, 0x8a, 0x62, 0x2b,
            0x12, 0x0f, 0x67, 0x21,
        ];
        let h: [u8; 32] = [
            0xaf, 0x2b, 0xdb, 0xe1, 0xaa, 0x9b, 0x6e, 0xc1, 0xe2, 0xad, 0xe1, 0xd6, 0x94, 0xf4,
            0x1f, 0xc7, 0x1a, 0x83, 0x1d, 0x02, 0x68, 0xe9, 0x89, 0x15, 0x62, 0x11, 0x3d, 0x8a,
            0x62, 0xad, 0xd1, 0xbf,
        ];
        let mut r = [0u8; 32];
        HmacDrbg::new(&x, &h).fill_bytes(&mut r);
        assert_eq!(
            r,
            [
                0xa6, 0xe3, 0xc5, 0x7d, 0xd0, 0x1a, 0xbe, 0x90, 0x08, 0x65, 0x38, 0x39, 0x83, 0x55,
                0xdd, 0x4c, 0x3b, 0x17, 0xaa, 0x87, 0x33, 0x82, 0xb0, 0xf2, 0x4d, 0x61, 0x29, 0x49,
                0x3d, 0x8a, 0xad, 0x60,
            ]
        );
    }
}
