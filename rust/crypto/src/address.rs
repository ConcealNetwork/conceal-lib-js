//! CryptoNote address encoding/decoding — create_address, decode_address.
//!
//! Conceal Network mainnet address prefix: 31444 (0x7AD4).
//! Integrated address prefix:             31445 (0x7AD5).
//! Subaddress prefix:                     31446 (0x7AD6).

use crate::{base58, keccak, keys};

pub const ADDRESS_PREFIX: u64 = 31444;
pub const INTEGRATED_ADDRESS_PREFIX: u64 = 31445;
pub const SUBADDRESS_PREFIX: u64 = 31446;

pub const ADDRESS_CHECKSUM_SIZE: usize = 4;
pub const INTEGRATED_ID_SIZE: usize = 8;

const PUBKEY_SIZE: usize = 32;

/// Decoded address fields (standard, integrated, or subaddress).
pub struct DecodedAddress {
    pub spend: [u8; 32],
    pub view: [u8; 32],
    pub int_payment_id: Option<[u8; INTEGRATED_ID_SIZE]>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AddressKind {
    Standard,
    Integrated,
    Subaddress,
}

/// Build the varint-encoded prefix bytes for a given numeric prefix.
fn prefix_bytes(prefix: u64) -> Vec<u8> {
    let mut out = Vec::new();
    keys::encode_varint_into(prefix, &mut out);
    out
}

fn match_prefix(dec: &[u8]) -> Result<(AddressKind, usize), String> {
    let candidates = [
        (AddressKind::Standard, ADDRESS_PREFIX),
        (AddressKind::Integrated, INTEGRATED_ADDRESS_PREFIX),
        (AddressKind::Subaddress, SUBADDRESS_PREFIX),
    ];
    for (kind, prefix) in candidates {
        let pb = prefix_bytes(prefix);
        if dec.starts_with(&pb) {
            return Ok((kind, pb.len()));
        }
    }
    Err("invalid address prefix".into())
}

fn expected_payload_len(kind: AddressKind, prefix_len: usize) -> usize {
    prefix_len
        + PUBKEY_SIZE
        + PUBKEY_SIZE
        + if kind == AddressKind::Integrated {
            INTEGRATED_ID_SIZE
        } else {
            0
        }
        + ADDRESS_CHECKSUM_SIZE
}

fn slice32(data: &[u8], start: usize) -> Result<[u8; 32], String> {
    data.get(start..start + PUBKEY_SIZE)
        .ok_or_else(|| String::from("invalid address length"))?
        .try_into()
        .map_err(|_| String::from("invalid address length"))
}

fn slice8(data: &[u8], start: usize) -> Result<[u8; INTEGRATED_ID_SIZE], String> {
    data.get(start..start + INTEGRATED_ID_SIZE)
        .ok_or_else(|| String::from("invalid address length"))?
        .try_into()
        .map_err(|_| String::from("invalid address length"))
}

fn verify_checksum(dec: &[u8]) -> Result<(), String> {
    if dec.len() < ADDRESS_CHECKSUM_SIZE {
        return Err("invalid address length".into());
    }
    let data_bytes = &dec[..dec.len() - ADDRESS_CHECKSUM_SIZE];
    let computed = keccak::keccak256_bytes(data_bytes);
    let checksum_start = dec.len() - ADDRESS_CHECKSUM_SIZE;
    if dec[checksum_start..] != computed[..ADDRESS_CHECKSUM_SIZE] {
        return Err("invalid address checksum".into());
    }
    Ok(())
}

/// Encode spend + view public keys into a Conceal address string.
/// `pubkeys_to_string` equivalent from Cn.ts.
pub fn pubkeys_to_string(spend_pub: &[u8; 32], view_pub: &[u8; 32]) -> String {
    let mut data = prefix_bytes(ADDRESS_PREFIX);
    data.extend_from_slice(spend_pub);
    data.extend_from_slice(view_pub);
    let checksum = keccak::keccak256_bytes(&data);
    data.extend_from_slice(&checksum[..ADDRESS_CHECKSUM_SIZE]);
    base58::encode(&data)
}

/// Encode an integrated address embedding an 8-byte payment ID.
pub fn encode_integrated_address(
    spend_pub: &[u8; 32],
    view_pub: &[u8; 32],
    payment_id: &[u8; INTEGRATED_ID_SIZE],
) -> String {
    let mut data = prefix_bytes(INTEGRATED_ADDRESS_PREFIX);
    data.extend_from_slice(spend_pub);
    data.extend_from_slice(view_pub);
    data.extend_from_slice(payment_id);
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
) -> ([u8; 32], [u8; 32], [u8; 32], [u8; 32], String) {
    let (spend_sec, spend_pub) = keys::generate_keys_bytes(seed);
    let second = keccak::keccak256_bytes(&spend_sec);
    let (view_sec, view_pub) = keys::generate_keys_bytes(&second);
    let public_addr = pubkeys_to_string(&spend_pub, &view_pub);
    (spend_sec, spend_pub, view_sec, view_pub, public_addr)
}

/// Decode a Conceal address string with integrated payment ID support.
///
/// Enforces an exact decoded length so trailing bytes cannot be appended to a
/// valid address and still pass checksum validation (address malleability).
pub fn decode_address_full(address: &str) -> Result<DecodedAddress, String> {
    let dec = base58::decode(address)?;
    let (kind, prefix_len) = match_prefix(&dec)?;

    if dec.len() != expected_payload_len(kind, prefix_len) {
        return Err("invalid address length".into());
    }

    let body_start = prefix_len;
    let spend = slice32(&dec, body_start)?;
    let view = slice32(&dec, body_start + PUBKEY_SIZE)?;

    let int_payment_id = if kind == AddressKind::Integrated {
        Some(slice8(&dec, body_start + PUBKEY_SIZE + PUBKEY_SIZE)?)
    } else {
        None
    };

    verify_checksum(&dec)?;

    Ok(DecodedAddress {
        spend,
        view,
        int_payment_id,
    })
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

    #[test]
    fn integrated_prefix_varint() {
        assert_eq!(
            bytes_to_hex(&prefix_bytes(INTEGRATED_ADDRESS_PREFIX)),
            "d5f501"
        );
    }

    /// Address roundtrip: create then decode must return matching keys.
    #[test]
    fn create_and_decode_roundtrip() {
        let seed = [1u8; 32];
        let (_, spend_pub, _, view_pub, addr) = create_address_from_seed(&seed);
        let decoded = decode_address_full(&addr).unwrap();
        assert_eq!(spend_pub, decoded.spend);
        assert_eq!(view_pub, decoded.view);
        assert_eq!(decoded.int_payment_id, None);
    }

    #[test]
    fn integrated_encode_decode_roundtrip() {
        let spend = [0x11u8; 32];
        let view = [0x22u8; 32];
        let payment_id = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0xaa];
        let addr = encode_integrated_address(&spend, &view, &payment_id);
        let decoded = decode_address_full(&addr).unwrap();
        assert_eq!(decoded.spend, spend);
        assert_eq!(decoded.view, view);
        assert_eq!(decoded.int_payment_id, Some(payment_id));
    }

    #[test]
    fn padded_address_rejected() {
        let seed = [1u8; 32];
        let (_, _, _, _, addr) = create_address_from_seed(&seed);
        let mut raw = base58::decode(&addr).unwrap();
        raw.push(0x00);
        let padded = base58::encode(&raw);
        assert!(decode_address_full(&padded).is_err());
    }

    /// All-zero seed produces a valid address.
    #[test]
    fn zero_seed_address() {
        let (_, _, _, _, addr) = create_address_from_seed(&[0u8; 32]);
        assert!(!addr.is_empty(), "address should not be empty");
        decode_address_full(&addr).unwrap();
    }

    /// Known-vector test for cross-checking against conceal-web-wallet JS output.
    #[test]
    fn known_vector_seed_ones() {
        let seed = [0x01u8; 32];
        let (spend_sec, spend_pub, view_sec, view_pub, addr) = create_address_from_seed(&seed);

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

        let decoded = decode_address_full(&addr).unwrap();
        assert_eq!(spend_pub, decoded.spend);
        assert_eq!(view_pub, decoded.view);
    }
}
