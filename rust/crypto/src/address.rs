//! CryptoNote address encoding/decoding — create_address, decode_address.
//!
//! Conceal Network mainnet address prefix: 31444 (0x7AD4).
//! Integrated address prefix:             31445 (0x7AD5).
//! Subaddress prefix:                     31446 (0x7AD6).

use crate::{base58, keccak, keys, utils};

pub const ADDRESS_PREFIX: u64 = 31444;
pub const INTEGRATED_ADDRESS_PREFIX: u64 = 31445;
pub const SUBADDRESS_PREFIX: u64 = 31446;

const ADDRESS_CHECKSUM_SIZE: usize = 4;

/// Build the varint-encoded prefix bytes for a given numeric prefix.
fn prefix_bytes(prefix: u64) -> Vec<u8> {
    let mut out = Vec::new();
    keys::encode_varint_into(prefix, &mut out);
    out
}

/// Encode spend + view public keys into a Conceal address string.
/// pubkeys_to_string equivalent from Cn.ts.
pub fn pubkeys_to_string(spend_pub: &[u8; 32], view_pub: &[u8; 32]) -> String {
    let mut data = prefix_bytes(ADDRESS_PREFIX);
    data.extend_from_slice(spend_pub);
    data.extend_from_slice(view_pub);
    let checksum = keccak::keccak256_bytes(&data);
    data.extend_from_slice(&checksum[..ADDRESS_CHECKSUM_SIZE]);
    base58::encode(&data)
}

/// Full wallet address generation from a 32-byte seed.
///
/// Matches Cn.ts `create_address` for a 64-char hex seed (the standard case):
///   spend = generate_keys(seed)
///   view  = generate_keys(cn_fast_hash(spend.sec))   // Monero-compatible variant
///
/// Returns (spend_sec, spend_pub, view_sec, view_pub, public_addr).
pub fn create_address_from_seed(
    seed: &[u8; 32],
) -> (
    [u8; 32],
    [u8; 32],
    [u8; 32],
    [u8; 32],
    String,
) {
    let (spend_sec, spend_pub) = keys::generate_keys_bytes(seed);
    let second = keccak::keccak256_bytes(&spend_sec);
    let (view_sec, view_pub) = keys::generate_keys_bytes(&second);
    let public_addr = pubkeys_to_string(&spend_pub, &view_pub);
    (spend_sec, spend_pub, view_sec, view_pub, public_addr)
}

/// Decode a Conceal address string.
///
/// Returns (spend_pub_hex, view_pub_hex) or an error.
pub fn decode_address_str(address: &str) -> Result<([u8; 32], [u8; 32]), String> {
    let dec = base58::decode(address)?;
    let dec_hex = utils::bytes_to_hex(&dec);

    // Determine expected prefix length by trying known prefixes.
    let exp_prefix = utils::bytes_to_hex(&prefix_bytes(ADDRESS_PREFIX));
    let exp_prefix_int = utils::bytes_to_hex(&prefix_bytes(INTEGRATED_ADDRESS_PREFIX));
    let exp_prefix_sub = utils::bytes_to_hex(&prefix_bytes(SUBADDRESS_PREFIX));

    let prefix_len = if dec_hex.starts_with(&exp_prefix) {
        exp_prefix.len()
    } else if dec_hex.starts_with(&exp_prefix_int) {
        exp_prefix_int.len()
    } else if dec_hex.starts_with(&exp_prefix_sub) {
        exp_prefix_sub.len()
    } else {
        return Err("invalid address prefix".into());
    };

    // Extract spend and view public keys (each 32 bytes = 64 hex chars).
    let spend_hex = &dec_hex[prefix_len..prefix_len + 64];
    let view_hex = &dec_hex[prefix_len + 64..prefix_len + 128];

    let spend = utils::hex_to_bytes32(spend_hex)?;
    let view = utils::hex_to_bytes32(view_hex)?;

    // Verify checksum.
    let data_bytes = &dec[..dec.len() - ADDRESS_CHECKSUM_SIZE];
    let computed = keccak::keccak256_bytes(data_bytes);
    let checksum_start = dec.len() - ADDRESS_CHECKSUM_SIZE;
    if dec[checksum_start..] != computed[..ADDRESS_CHECKSUM_SIZE] {
        return Err("invalid address checksum".into());
    }

    Ok((spend, view))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::bytes_to_hex;

    /// Verify varint encoding for the Conceal prefix 31444.
    #[test]
    fn prefix_varint_31444() {
        let p = prefix_bytes(ADDRESS_PREFIX);
        assert_eq!(bytes_to_hex(&p), "d4f501");
    }

    /// Address roundtrip: create then decode must return matching keys.
    #[test]
    fn create_and_decode_roundtrip() {
        let seed = [1u8; 32];
        let (_, spend_pub, _, view_pub, addr) = create_address_from_seed(&seed);
        let (decoded_spend, decoded_view) = decode_address_str(&addr).unwrap();
        assert_eq!(spend_pub, decoded_spend);
        assert_eq!(view_pub, decoded_view);
    }

    /// All-zero seed produces a valid address.
    #[test]
    fn zero_seed_address() {
        let (_, _, _, _, addr) = create_address_from_seed(&[0u8; 32]);
        assert!(addr.len() > 0, "address should not be empty");
        decode_address_str(&addr).unwrap();
    }

    /// Known-vector test for cross-checking against conceal-web-wallet JS output.
    ///
    /// Seed: 32 bytes of 0x01 ("0101...01" hex, 64 chars).
    ///
    /// Expected values computed by running Cn.ts `create_address` in the
    /// web wallet with seed = "0101010101010101010101010101010101010101010101010101010101010101".
    ///
    /// To regenerate: open browser console on conceal-web-wallet, call
    ///   Cn.create_address("0101...01")
    /// and verify these values match.
    #[test]
    fn known_vector_seed_ones() {
        let seed = [0x01u8; 32];
        let (spend_sec, spend_pub, view_sec, view_pub, addr) = create_address_from_seed(&seed);

        // spend.sec = sc_reduce32(seed).  0x01*32 is already < l, so unchanged.
        assert_eq!(
            bytes_to_hex(&spend_sec),
            "0101010101010101010101010101010101010101010101010101010101010101"
        );
        assert_eq!(
            bytes_to_hex(&spend_pub),
            "130ae82201d7072e6fbfc0a1884fb54636554d14945b799125cf7ce38d477f51"
        );
        assert_eq!(
            bytes_to_hex(&view_sec),
            "eb51211073fdd85629dda967a86ead8717884c2d66667c67a90508214bd8ba0c"
        );
        assert_eq!(
            bytes_to_hex(&view_pub),
            "fa17d335e10b66cc28e09e2de59dc7e8a3d11bcf579d6d493b94c3d1f2081562"
        );
        assert_eq!(
            addr,
            "ccx7DPvKYficy3QUqegFJFELGa3CE61AKGJRQgyBMe6xCxcbqXfRa722ucLqFsm4hiTPfzf7JTzwxTLEp2jR4BGm1JmVe2rDkq"
        );

        // Round-trip consistency.
        let (decoded_spend, decoded_view) = decode_address_str(&addr).unwrap();
        assert_eq!(spend_pub, decoded_spend);
        assert_eq!(view_pub, decoded_view);

        // Print values for JS cross-check (visible with `cargo test -- --nocapture`).
        println!("spend.sec = {}", bytes_to_hex(&spend_sec));
        println!("spend.pub = {}", bytes_to_hex(&spend_pub));
        println!("view.sec  = {}", bytes_to_hex(&view_sec));
        println!("view.pub  = {}", bytes_to_hex(&view_pub));
        println!("addr      = {addr}");
    }
}
