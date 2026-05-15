//! High-level CryptoNote key operations — port of crypto.h.
//!
//! References (all from conceal-core/src/crypto/crypto.h):
//!   generate_keys, generate_key_derivation, derive_public_key, derive_secret_key,
//!   hash_to_scalar, generate_key_image.

use crate::{ge, keccak, scalar};

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Encode a u64 as a CryptoNote varint (LEB128) appended to `out`.
pub(crate) fn encode_varint_into(mut n: u64, out: &mut Vec<u8>) {
    loop {
        if n < 0x80 {
            out.push(n as u8);
            break;
        }
        out.push(((n & 0x7F) | 0x80) as u8);
        n >>= 7;
    }
}

/// derivation_to_scalar: hash_to_scalar(derivation_bytes || varint(out_index))
/// This is the inner step shared by derive_public_key and derive_secret_key.
fn derivation_to_scalar(derivation: &[u8; 32], out_index: u32) -> [u8; 32] {
    let mut buf = derivation.to_vec();
    encode_varint_into(out_index as u64, &mut buf);
    hash_to_scalar_bytes(&buf)
}

/// hash_to_scalar over raw bytes: keccak256(data) then sc_reduce32.
fn hash_to_scalar_bytes(data: &[u8]) -> [u8; 32] {
    let hash = keccak::keccak256_bytes(data);
    scalar::sc_reduce32_bytes(&hash)
}

// ---------------------------------------------------------------------------
// Public (used by lib.rs WASM exports)
// ---------------------------------------------------------------------------

/// generate_keys: sec = sc_reduce32(seed), pub = ge_scalarmult_base(sec).
pub fn generate_keys_bytes(seed: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let sec = scalar::sc_reduce32_bytes(seed);
    let pub_key = ge::ge_scalarmult_base_bytes(&sec);
    (sec, pub_key)
}

/// hash_to_scalar: cn_fast_hash(hex_data) → sc_reduce32 → hex.
/// Input is raw bytes (caller handles hex decoding).
pub fn hash_to_scalar_pub(data: &[u8]) -> [u8; 32] {
    hash_to_scalar_bytes(data)
}

/// generate_key_derivation: 8 × (sec_scalar × pub_point).
/// Ref: crypto.h generate_key_derivation(pub, sec, derivation)
pub fn generate_key_derivation_bytes(
    pub_key: &[u8; 32],
    sec_key: &[u8; 32],
) -> Result<[u8; 32], String> {
    let p = ge::ge_scalarmult_bytes(pub_key, sec_key)?;
    ge::ge_mul8_bytes(&p)
}

/// derive_public_key: pub_point + derivation_to_scalar(derivation, out_index) × B.
/// Ref: crypto.h derive_public_key(derivation, output_index, base, derived_key)
pub fn derive_public_key_bytes(
    derivation: &[u8; 32],
    out_index: u32,
    base_pub: &[u8; 32],
) -> Result<[u8; 32], String> {
    let scalar_bytes = derivation_to_scalar(derivation, out_index);
    let scalar = curve25519_dalek::scalar::Scalar::from_bytes_mod_order(scalar_bytes);
    let sb = (scalar * curve25519_dalek::constants::ED25519_BASEPOINT_POINT)
        .compress()
        .to_bytes();
    ge::ge_add_bytes(base_pub, &sb)
}

/// derive_secret_key: sc_add(sec, derivation_to_scalar(derivation, out_index)).
/// Ref: crypto.h derive_secret_key(derivation, output_index, base, derived_key)
pub fn derive_secret_key_bytes(
    derivation: &[u8; 32],
    out_index: u32,
    base_sec: &[u8; 32],
) -> [u8; 32] {
    let s = derivation_to_scalar(derivation, out_index);
    scalar::sc_add_bytes(base_sec, &s)
}

/// generate_key_image: public_key × secret_key (using hash-to-point for key image).
/// Placeholder — full impl needs ge_fromfe_frombytes_vartime (hash-to-curve).
#[allow(dead_code)]
pub fn generate_key_image_bytes(
    pub_key: &[u8; 32],
    sec_key: &[u8; 32],
) -> Result<[u8; 32], String> {
    ge::ge_scalarmult_bytes(pub_key, sec_key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::bytes_to_hex;

    /// Round-trip: generate_key_derivation then derive_secret_key then derive_public_key
    /// must produce a consistent public key from the derived private key.
    #[test]
    fn derive_key_roundtrip() {
        // All-zero seed → deterministic spend keypair
        let seed = [0u8; 32];
        let (spend_sec, spend_pub) = generate_keys_bytes(&seed);

        // Use spend_sec as the "transaction secret" and spend_pub as "transaction public"
        // to get a derivation (this is not the normal wallet flow but tests the math)
        let derivation = generate_key_derivation_bytes(&spend_pub, &spend_sec).unwrap();

        let derived_sec = derive_secret_key_bytes(&derivation, 0, &spend_sec);
        let derived_pub_from_sec = crate::ge::ge_scalarmult_base_bytes(&derived_sec);
        let derived_pub = derive_public_key_bytes(&derivation, 0, &spend_pub).unwrap();

        assert_eq!(derived_pub, derived_pub_from_sec,
            "derive_public_key and derive_secret_key + ge_scalarmult_base must agree");
    }

    /// Verify deterministic output for a known zero seed.
    #[test]
    fn generate_keys_zero_seed() {
        let (sec, pub_key) = generate_keys_bytes(&[0u8; 32]);
        // sc_reduce32(0) = 0
        assert_eq!(sec, [0u8; 32]);
        // ge_scalarmult_base(0) is the identity point
        let _ = bytes_to_hex(&pub_key); // just ensure it doesn't panic
    }
}
