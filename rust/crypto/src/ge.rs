//! Ed25519 group (Edwards curve) operations — port of crypto-ops.h ge_* functions.
//!
//! Points are passed as 32-byte compressed Edwards y representation
//! (the standard Ed25519 encoding: y-coordinate little-endian, sign of x in the
//! MSB of the last byte).

use curve25519_dalek::{
    constants::ED25519_BASEPOINT_POINT,
    edwards::{CompressedEdwardsY, EdwardsPoint},
    scalar::Scalar,
};

/// ge_scalarmult_base: B × scalar, where B is the Ed25519 base point.
/// Equivalent to generating a public key from a private (spend) key.
pub fn ge_scalarmult_base_bytes(scalar: &[u8; 32]) -> [u8; 32] {
    let s = Scalar::from_bytes_mod_order(*scalar);
    (s * ED25519_BASEPOINT_POINT).compress().to_bytes()
}

/// Decompress a 32-byte compressed Edwards point.
pub fn decompress_point(bytes: &[u8; 32]) -> Result<EdwardsPoint, String> {
    CompressedEdwardsY(*bytes)
        .decompress()
        .ok_or_else(|| "invalid compressed Edwards point".into())
}

/// ge_scalarmult: point × scalar.
pub fn ge_scalarmult_bytes(point: &[u8; 32], scalar: &[u8; 32]) -> Result<[u8; 32], String> {
    let p = decompress_point(point)?;
    let s = Scalar::from_bytes_mod_order(*scalar);
    Ok((p * s).compress().to_bytes())
}

/// ge_mul8: multiply a point by the cofactor 8.
pub fn ge_mul8_bytes(point: &[u8; 32]) -> Result<[u8; 32], String> {
    let p = decompress_point(point)?;
    Ok(p.mul_by_cofactor().compress().to_bytes())
}

/// ge_add: point_a + point_b (Edwards point addition).
pub fn ge_add_bytes(a: &[u8; 32], b: &[u8; 32]) -> Result<[u8; 32], String> {
    let pa = decompress_point(a)?;
    let pb = decompress_point(b)?;
    Ok((pa + pb).compress().to_bytes())
}

/// ge_tobytes / ge_p3_tobytes: compress an Edwards point to 32 bytes.
/// In our hex-in/hex-out API this is a no-op (points are already compressed).
pub fn ge_tobytes_bytes(point: &[u8; 32]) -> Result<[u8; 32], String> {
    // Validate that the point is on the curve by decompressing.
    let _ = decompress_point(point)?;
    Ok(*point)
}

/// ge_frombytes_vartime: decompress and recompress — validates a point is on the curve.
/// Returns the canonical compressed encoding.
pub fn ge_frombytes_bytes(point: &[u8; 32]) -> Result<[u8; 32], String> {
    Ok(decompress_point(point)?.compress().to_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::bytes_to_hex;

    /// The basepoint compressed y-coordinate for Ed25519.
    const BASEPOINT_HEX: &str =
        "5866666666666666666666666666666666666666666666666666666666666666";

    #[test]
    fn basepoint_scalar_one() {
        let mut scalar = [0u8; 32];
        scalar[0] = 1;
        let pub_key = ge_scalarmult_base_bytes(&scalar);
        assert_eq!(bytes_to_hex(&pub_key), BASEPOINT_HEX);
    }

    #[test]
    fn mul8_of_basepoint_is_not_zero() {
        // 8*B is a valid non-identity point on the curve.
        let bp = {
            let mut s = [0u8; 32];
            s[0] = 1;
            ge_scalarmult_base_bytes(&s)
        };
        let result = ge_mul8_bytes(&bp).unwrap();
        assert_ne!(result, [0u8; 32]);
    }

    #[test]
    fn add_then_double() {
        let mut scalar = [0u8; 32];
        scalar[0] = 3;
        let p3b = ge_scalarmult_base_bytes(&scalar);

        scalar[0] = 1;
        let p1b = ge_scalarmult_base_bytes(&scalar);
        scalar[0] = 2;
        let p2b = ge_scalarmult_base_bytes(&scalar);

        // 1*B + 2*B == 3*B
        let sum = ge_add_bytes(&p1b, &p2b).unwrap();
        assert_eq!(sum, p3b);
    }
}
