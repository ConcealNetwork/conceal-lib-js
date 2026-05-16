//! CryptoNote cryptographic primitives for Conceal Network, compiled to WebAssembly.
//!
//! All functions take and return hex strings to keep the JS↔WASM boundary simple
//! and avoid memory management in callers.  Function names match the identifiers
//! used in `conceal-web-wallet/src/model/Cn.ts` exactly.
//!
//! ## Module layout
//!
//! | Module | Contents |
//! |--------|---------|
//! | `keccak` | `keccak256_bytes` (raw) |
//! | `scalar` | `sc_reduce32`, `sc_add`, `sc_sub`, `sc_mulsub`, `sc_0`, `sc_check` |
//! | `ge` | `ge_scalarmult_base`, `ge_scalarmult`, `ge_mul8`, `ge_add`, `ge_tobytes` |
//! | `keys` | `generate_keys`, `generate_key_derivation`, `derive_public_key`, `derive_secret_key`, `hash_to_scalar` |
//! | `address` | `create_address`, `decode_address` |
//! | `base58` | CryptoNote Base58 encode/decode |
//! | `utils` | hex conversion helpers |

mod address;
mod base58;
mod ge;
mod keccak;
mod keys;
mod scalar;
mod utils;

use utils::{bytes_to_hex, hex_to_bytes, hex_to_bytes32};
use wasm_bindgen::prelude::*;

/// Plain JS object `{ sec, pub }` for `generate_keys` / nested key pairs.
#[derive(serde::Serialize)]
struct KeyPairJs {
    sec: String,
    #[serde(rename = "pub")]
    pub_key: String,
}

/// Plain JS object for `create_address`.
#[derive(serde::Serialize)]
struct AddressJs {
    spend: KeyPairJs,
    view: KeyPairJs,
    public_addr: String,
}

/// Plain JS object for `decode_address`.
#[derive(serde::Serialize)]
struct DecodedAddressJs {
    spend: String,
    view: String,
    #[serde(rename = "intPaymentId")]
    int_payment_id: Option<()>,
}

fn to_js_value<T: serde::Serialize>(value: &T) -> Result<JsValue, JsValue> {
    serde_wasm_bindgen::to_value(value).map_err(|e| JsValue::from_str(&e.to_string()))
}

// ---------------------------------------------------------------------------
// Hash
// ---------------------------------------------------------------------------

/// cn_fast_hash: Keccak-256 of hex-decoded input.
/// Matches `CnUtils.cn_fast_hash(hex)` in Cn.ts.
#[wasm_bindgen]
pub fn cn_fast_hash(data_hex: &str) -> Result<String, JsValue> {
    let data = hex_to_bytes(data_hex).map_err(|e| JsValue::from_str(&e))?;
    Ok(bytes_to_hex(&keccak::keccak256_bytes(&data)))
}

/// hash_to_scalar: cn_fast_hash then sc_reduce32.
/// Matches `Cn.hash_to_scalar(hex)` in Cn.ts.
#[wasm_bindgen]
pub fn hash_to_scalar(data_hex: &str) -> Result<String, JsValue> {
    let data = hex_to_bytes(data_hex).map_err(|e| JsValue::from_str(&e))?;
    let result = keys::hash_to_scalar_pub(&data);
    Ok(bytes_to_hex(&result))
}

// ---------------------------------------------------------------------------
// Scalar arithmetic
// ---------------------------------------------------------------------------

/// sc_reduce32: reduce a 32-byte scalar mod the Ed25519 group order.
#[wasm_bindgen]
pub fn sc_reduce32(hex: &str) -> Result<String, JsValue> {
    let bytes = hex_to_bytes32(hex).map_err(|e| JsValue::from_str(&e))?;
    Ok(bytes_to_hex(&scalar::sc_reduce32_bytes(&bytes)))
}

/// sc_add: (a + b) mod l.
#[wasm_bindgen]
pub fn sc_add(a_hex: &str, b_hex: &str) -> Result<String, JsValue> {
    let a = hex_to_bytes32(a_hex).map_err(|e| JsValue::from_str(&e))?;
    let b = hex_to_bytes32(b_hex).map_err(|e| JsValue::from_str(&e))?;
    Ok(bytes_to_hex(&scalar::sc_add_bytes(&a, &b)))
}

/// sc_sub: (a - b) mod l.
#[wasm_bindgen]
pub fn sc_sub(a_hex: &str, b_hex: &str) -> Result<String, JsValue> {
    let a = hex_to_bytes32(a_hex).map_err(|e| JsValue::from_str(&e))?;
    let b = hex_to_bytes32(b_hex).map_err(|e| JsValue::from_str(&e))?;
    Ok(bytes_to_hex(&scalar::sc_sub_bytes(&a, &b)))
}

/// sc_mulsub: (c - a*b) mod l.
#[wasm_bindgen]
pub fn sc_mulsub(a_hex: &str, b_hex: &str, c_hex: &str) -> Result<String, JsValue> {
    let a = hex_to_bytes32(a_hex).map_err(|e| JsValue::from_str(&e))?;
    let b = hex_to_bytes32(b_hex).map_err(|e| JsValue::from_str(&e))?;
    let c = hex_to_bytes32(c_hex).map_err(|e| JsValue::from_str(&e))?;
    Ok(bytes_to_hex(&scalar::sc_mulsub_bytes(&a, &b, &c)))
}

/// sc_0: returns a zero scalar (32 zero bytes as hex).
#[wasm_bindgen]
pub fn sc_0() -> String {
    bytes_to_hex(&scalar::sc_0_bytes())
}

/// sc_check: returns true if the scalar is canonical (< group order l).
#[wasm_bindgen]
pub fn sc_check(hex: &str) -> Result<bool, JsValue> {
    let bytes = hex_to_bytes32(hex).map_err(|e| JsValue::from_str(&e))?;
    Ok(scalar::sc_check_bytes(&bytes))
}

// ---------------------------------------------------------------------------
// Group (Edwards curve) operations
// ---------------------------------------------------------------------------

/// ge_scalarmult_base: scalar × base point.  Returns compressed public key hex.
/// Also serves as `sec_key_to_pub` — matches nacl.ll.ge_scalarmult_base behaviour.
#[wasm_bindgen]
pub fn ge_scalarmult_base(scalar_hex: &str) -> Result<String, JsValue> {
    let s = hex_to_bytes32(scalar_hex).map_err(|e| JsValue::from_str(&e))?;
    Ok(bytes_to_hex(&ge::ge_scalarmult_base_bytes(&s)))
}

/// ge_scalarmult: point × scalar.
#[wasm_bindgen]
pub fn ge_scalarmult(point_hex: &str, scalar_hex: &str) -> Result<String, JsValue> {
    let p = hex_to_bytes32(point_hex).map_err(|e| JsValue::from_str(&e))?;
    let s = hex_to_bytes32(scalar_hex).map_err(|e| JsValue::from_str(&e))?;
    ge::ge_scalarmult_bytes(&p, &s)
        .map(|r| bytes_to_hex(&r))
        .map_err(|e| JsValue::from_str(&e))
}

/// ge_mul8: multiply point by cofactor 8.
#[wasm_bindgen]
pub fn ge_mul8(point_hex: &str) -> Result<String, JsValue> {
    let p = hex_to_bytes32(point_hex).map_err(|e| JsValue::from_str(&e))?;
    ge::ge_mul8_bytes(&p)
        .map(|r| bytes_to_hex(&r))
        .map_err(|e| JsValue::from_str(&e))
}

/// ge_add: point_a + point_b (Edwards addition).
#[wasm_bindgen]
pub fn ge_add(a_hex: &str, b_hex: &str) -> Result<String, JsValue> {
    let a = hex_to_bytes32(a_hex).map_err(|e| JsValue::from_str(&e))?;
    let b = hex_to_bytes32(b_hex).map_err(|e| JsValue::from_str(&e))?;
    ge::ge_add_bytes(&a, &b)
        .map(|r| bytes_to_hex(&r))
        .map_err(|e| JsValue::from_str(&e))
}

/// ge_tobytes / ge_p3_tobytes: returns the compressed point (validates it is on curve).
#[wasm_bindgen]
pub fn ge_tobytes(point_hex: &str) -> Result<String, JsValue> {
    let p = hex_to_bytes32(point_hex).map_err(|e| JsValue::from_str(&e))?;
    ge::ge_tobytes_bytes(&p)
        .map(|r| bytes_to_hex(&r))
        .map_err(|e| JsValue::from_str(&e))
}

/// ge_p3_tobytes: alias for ge_tobytes.
#[wasm_bindgen]
pub fn ge_p3_tobytes(point_hex: &str) -> Result<String, JsValue> {
    ge_tobytes(point_hex)
}

/// ge_frombytes_vartime: validate and canonicalise a compressed Edwards point.
#[wasm_bindgen]
pub fn ge_frombytes_vartime(point_hex: &str) -> Result<String, JsValue> {
    let p = hex_to_bytes32(point_hex).map_err(|e| JsValue::from_str(&e))?;
    ge::ge_frombytes_bytes(&p)
        .map(|r| bytes_to_hex(&r))
        .map_err(|e| JsValue::from_str(&e))
}

// ---------------------------------------------------------------------------
// High-level key operations
// ---------------------------------------------------------------------------

/// generate_keys: sec = sc_reduce32(seed), pub = ge_scalarmult_base(sec).
/// Returns `{sec: hex, pub: hex}`.  Matches `Cn.generate_keys(seed)`.
#[wasm_bindgen]
pub fn generate_keys(seed_hex: &str) -> Result<JsValue, JsValue> {
    let seed = hex_to_bytes32(seed_hex).map_err(|e| JsValue::from_str(&e))?;
    let (sec, pub_key) = keys::generate_keys_bytes(&seed);
    to_js_value(&KeyPairJs {
        sec: bytes_to_hex(&sec),
        pub_key: bytes_to_hex(&pub_key),
    })
}

/// generate_key_derivation: 8 × (sec_scalar × pub_point).
/// Matches `CnNativeBride.generate_key_derivation(pub, sec)`.
#[wasm_bindgen]
pub fn generate_key_derivation(pub_hex: &str, sec_hex: &str) -> Result<String, JsValue> {
    let pub_key = hex_to_bytes32(pub_hex).map_err(|e| JsValue::from_str(&e))?;
    let sec_key = hex_to_bytes32(sec_hex).map_err(|e| JsValue::from_str(&e))?;
    keys::generate_key_derivation_bytes(&pub_key, &sec_key)
        .map(|r| bytes_to_hex(&r))
        .map_err(|e| JsValue::from_str(&e))
}

/// derive_public_key: base_pub + derivation_to_scalar(derivation, index) × B.
/// Matches `CnNativeBride.derive_public_key(derivation, index, pub)`.
#[wasm_bindgen]
pub fn derive_public_key(derivation_hex: &str, out_index: u32, base_pub_hex: &str) -> Result<String, JsValue> {
    let derivation = hex_to_bytes32(derivation_hex).map_err(|e| JsValue::from_str(&e))?;
    let base_pub = hex_to_bytes32(base_pub_hex).map_err(|e| JsValue::from_str(&e))?;
    keys::derive_public_key_bytes(&derivation, out_index, &base_pub)
        .map(|r| bytes_to_hex(&r))
        .map_err(|e| JsValue::from_str(&e))
}

/// derive_secret_key: sc_add(base_sec, derivation_to_scalar(derivation, index)).
/// Matches `CnNativeBride.derive_secret_key(derivation, index, sec)`.
#[wasm_bindgen]
pub fn derive_secret_key(derivation_hex: &str, out_index: u32, base_sec_hex: &str) -> Result<String, JsValue> {
    let derivation = hex_to_bytes32(derivation_hex).map_err(|e| JsValue::from_str(&e))?;
    let base_sec = hex_to_bytes32(base_sec_hex).map_err(|e| JsValue::from_str(&e))?;
    Ok(bytes_to_hex(&keys::derive_secret_key_bytes(&derivation, out_index, &base_sec)))
}

// ---------------------------------------------------------------------------
// Address
// ---------------------------------------------------------------------------

/// create_address: full wallet key generation from a 32-byte reduced seed.
/// Returns `{spend:{sec,pub}, view:{sec,pub}, public_addr}`.
/// Matches `Cn.create_address(seed)` for 64-char hex input.
#[wasm_bindgen]
pub fn create_address(seed_hex: &str) -> Result<JsValue, JsValue> {
    let seed = hex_to_bytes32(seed_hex).map_err(|e| JsValue::from_str(&e))?;
    let (spend_sec, spend_pub, view_sec, view_pub, public_addr) =
        address::create_address_from_seed(&seed);
    to_js_value(&AddressJs {
        spend: KeyPairJs {
            sec: bytes_to_hex(&spend_sec),
            pub_key: bytes_to_hex(&spend_pub),
        },
        view: KeyPairJs {
            sec: bytes_to_hex(&view_sec),
            pub_key: bytes_to_hex(&view_pub),
        },
        public_addr,
    })
}

/// decode_address: validate and extract spend/view public keys from an address string.
/// Returns `{spend: hex, view: hex, intPaymentId: null}`.
/// Matches `Cn.decode_address(address)`.
#[wasm_bindgen]
pub fn decode_address(address: &str) -> Result<JsValue, JsValue> {
    let (spend, view) =
        address::decode_address_str(address).map_err(|e| JsValue::from_str(&e))?;
    to_js_value(&DecodedAddressJs {
        spend: bytes_to_hex(&spend),
        view: bytes_to_hex(&view),
        int_payment_id: None,
    })
}
