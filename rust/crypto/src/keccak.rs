//! Keccak-256 hash (cn_fast_hash) — port of hash-ops.h / keccak.h.
//!
//! CryptoNote uses raw Keccak-256, not SHA3-256.  The difference is the
//! domain-separation padding byte (0x01 for Keccak, 0x06 for SHA3).
//! `tiny-keccak`'s `Keccak::v256()` matches the CryptoNote variant. ✓

use tiny_keccak::{Hasher, Keccak};

/// Keccak-256 over raw bytes, returning 32 bytes.
pub fn keccak256_bytes(data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut h = Keccak::v256();
    h.update(data);
    h.finalize(&mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::bytes_to_hex;

    /// Empty input keccak-256 reference vector.
    #[test]
    fn empty_hash() {
        let hash = keccak256_bytes(&[]);
        // keccak256("") = c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470
        assert_eq!(
            bytes_to_hex(&hash),
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
        );
    }
}
