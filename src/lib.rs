use solana_hmac_sha256::HmacSha256;

/// # HmacDrbg
/// 
/// Sha256 Hmac deterministic random bit generator
#[derive(Clone)]
pub struct HmacDrbg {
    k: HmacSha256,
    v: [u8;32]
}

impl HmacDrbg {
    pub fn new(private_key: &[u8; 32], message_hash: &[u8; 32]) -> Self {
        let mut k = HmacSha256::new(&[0u8;32]);
        let mut v = [1u8;32];

        // k.update(&[0u8;32]);
        for i in 0..=1 {
            k.update(&v);
            k.update(&[i]);
            k.update(private_key);
            k.update(message_hash);
            k = HmacSha256::new(&k.finalize());
            k.update(&v);
            v.clone_from_slice(&k.finalize_reset());
        }
        Self { k, v }
    }

    pub fn fill_bytes(&mut self, out: &mut [u8]) {
        for out_chunk in out.chunks_mut(self.v.len()) {
            self.k.update(&self.v);
            self.v.clone_from_slice(&self.k.finalize_reset());
            out_chunk.copy_from_slice(&self.v[..out_chunk.len()]);
        }
        self.k.update(&self.v);
        self.k.update(&[0x00]);
        self.k = HmacSha256::new(&self.k.finalize_reset());
        self.k.update(&self.v);
        self.v.clone_from_slice(&self.k.finalize_reset());
    }
}

#[cfg(test)]
mod tests {
    use crate::HmacDrbg;

    #[test]
    pub fn main() {
        let x: [u8;32] = [0xc9, 0xaf, 0xa9, 0xd8, 0x45, 0xba, 0x75, 0x16, 0x6b, 0x5c, 0x21, 0x57, 0x67, 0xb1, 0xd6, 0x93, 0x4e, 0x50, 0xc3, 0xdb, 0x36, 0xe8, 0x9b, 0x12, 0x7b, 0x8a, 0x62, 0x2b, 0x12, 0x0f, 0x67, 0x21];
        let h: [u8;32] = [0xaf, 0x2b, 0xdb, 0xe1, 0xaa, 0x9b, 0x6e, 0xc1, 0xe2, 0xad, 0xe1, 0xd6, 0x94, 0xf4, 0x1f, 0xc7, 0x1a, 0x83, 0x1d, 0x02, 0x68, 0xe9, 0x89, 0x15, 0x62, 0x11, 0x3d, 0x8a, 0x62, 0xad, 0xd1, 0xbf];
        let mut r = [0u8;32];
        HmacDrbg::new(&x, &h).fill_bytes(&mut r);
        assert_eq!(r, [0xa6, 0xe3, 0xc5, 0x7d, 0xd0, 0x1a, 0xbe, 0x90, 0x08, 0x65, 0x38, 0x39, 0x83, 0x55, 0xdd, 0x4c, 0x3b, 0x17, 0xaa, 0x87, 0x33, 0x82, 0xb0, 0xf2, 0x4d, 0x61, 0x29, 0x49, 0x3d, 0x8a, 0xad, 0x60]);
    }
}