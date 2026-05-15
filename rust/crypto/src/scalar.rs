//! Ed25519 scalar arithmetic — port of crypto-ops.h sc_* functions.
//!
//! All scalars are 32-byte little-endian representations of integers modulo
//! the Ed25519 group order l.  `curve25519-dalek`'s `Scalar` type enforces
//! canonicality and handles all reduction automatically.

use curve25519_dalek::scalar::Scalar;

/// sc_reduce32: reduce a 32-byte scalar modulo l.
pub fn sc_reduce32_bytes(bytes: &[u8; 32]) -> [u8; 32] {
    Scalar::from_bytes_mod_order(*bytes).to_bytes()
}

/// sc_add: (a + b) mod l.
pub fn sc_add_bytes(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    (Scalar::from_bytes_mod_order(*a) + Scalar::from_bytes_mod_order(*b)).to_bytes()
}

/// sc_sub: (a - b) mod l.
pub fn sc_sub_bytes(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    (Scalar::from_bytes_mod_order(*a) - Scalar::from_bytes_mod_order(*b)).to_bytes()
}

/// sc_mulsub: (c - a*b) mod l.
pub fn sc_mulsub_bytes(a: &[u8; 32], b: &[u8; 32], c: &[u8; 32]) -> [u8; 32] {
    let sa = Scalar::from_bytes_mod_order(*a);
    let sb = Scalar::from_bytes_mod_order(*b);
    let sc = Scalar::from_bytes_mod_order(*c);
    (sc - sa * sb).to_bytes()
}

/// sc_0: zero scalar.
pub fn sc_0_bytes() -> [u8; 32] {
    [0u8; 32]
}

/// sc_check: true if bytes are a canonical scalar (< l).
pub fn sc_check_bytes(bytes: &[u8; 32]) -> bool {
    // If from_bytes_mod_order doesn't change the value, it was already reduced.
    Scalar::from_bytes_mod_order(*bytes).to_bytes() == *bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reduce32_zero() {
        assert_eq!(sc_reduce32_bytes(&[0u8; 32]), [0u8; 32]);
    }

    #[test]
    fn add_then_sub() {
        let a = sc_reduce32_bytes(&[1u8; 32]);
        let b = sc_reduce32_bytes(&[2u8; 32]);
        let sum = sc_add_bytes(&a, &b);
        let diff = sc_sub_bytes(&sum, &b);
        assert_eq!(diff, a);
    }

    #[test]
    fn check_zero_is_canonical() {
        assert!(sc_check_bytes(&[0u8; 32]));
    }
}
