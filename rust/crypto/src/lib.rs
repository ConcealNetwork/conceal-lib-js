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
//! | `keys` | `generate_keys`, `generate_key_derivation`, `derive_public_key`, `derive_secret_key`, `hash_to_scalar`, `generate_key_image` |
//! | `scan` | `scan_receive_outputs`, `scan_receive_outputs_batch` |
//! | `signature` | `generate_signature`, `generate_ring_signature`, `check_tx_proof` |
//! | `address` | `create_address`, `encode_address`, `encode_integrated_address`, `decode_address` |
//! | `base58` | CryptoNote Base58 encode/decode |
//! | `utils` | hex conversion helpers |

mod address;
mod base58;
mod ffi;
mod ge;
mod keccak;
mod keys;
mod rng;
mod scalar;
mod scan;
mod signature;
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
    int_payment_id: Option<String>,
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

/// One WASM call: `generate_key_derivation` then `derive_public_key` for each output.
/// `output_indices[i]` is the derivation index; `output_keys_hex[i]` is the on-chain key (64 hex).
#[wasm_bindgen]
pub fn scan_receive_outputs(
    tx_pub_hex: &str,
    view_sec_hex: &str,
    spend_pub_hex: &str,
    output_indices: Vec<u32>,
    output_keys_hex: Vec<String>,
) -> Result<bool, JsValue> {
    scan::scan_receive_outputs_hex(
        tx_pub_hex,
        view_sec_hex,
        spend_pub_hex,
        &output_indices,
        &output_keys_hex,
    )
    .map_err(|e| JsValue::from_str(&e))
}

/// Batch receive scan: one WASM call for many transactions (shared view/spend keys).
///
/// `tx_offsets.len() == tx_pub_hex.len() + 1`; slice `i` is
/// `output_indices[tx_offsets[i]..tx_offsets[i+1]]`. Empty `tx_pub_hex[i]` → `0`.
/// Returns `1` / `0` per tx (`Vec<u32>` for wasm-bindgen; map to boolean in JS).
#[wasm_bindgen]
pub fn scan_receive_outputs_batch(
    view_sec_hex: &str,
    spend_pub_hex: &str,
    tx_pub_hex: Vec<String>,
    output_indices: Vec<u32>,
    output_keys_hex: Vec<String>,
    tx_offsets: Vec<u32>,
) -> Result<Vec<u32>, JsValue> {
    scan::scan_receive_outputs_batch_hex(
        view_sec_hex,
        spend_pub_hex,
        &tx_pub_hex,
        &output_indices,
        &output_keys_hex,
        &tx_offsets,
    )
    .map(|flags| flags.into_iter().map(u32::from).collect())
    .map_err(|e| JsValue::from_str(&e))
}

/// derive_public_key: base_pub + derivation_to_scalar(derivation, index) × B.
/// Matches `CnNativeBride.derive_public_key(derivation, index, pub)`.
#[wasm_bindgen]
pub fn derive_public_key(
    derivation_hex: &str,
    out_index: u32,
    base_pub_hex: &str,
) -> Result<String, JsValue> {
    let derivation = hex_to_bytes32(derivation_hex).map_err(|e| JsValue::from_str(&e))?;
    let base_pub = hex_to_bytes32(base_pub_hex).map_err(|e| JsValue::from_str(&e))?;
    keys::derive_public_key_bytes(&derivation, out_index, &base_pub)
        .map(|r| bytes_to_hex(&r))
        .map_err(|e| JsValue::from_str(&e))
}

/// derive_secret_key: sc_add(base_sec, derivation_to_scalar(derivation, index)).
/// Matches `CnNativeBride.derive_secret_key(derivation, index, sec)`.
#[wasm_bindgen]
pub fn derive_secret_key(
    derivation_hex: &str,
    out_index: u32,
    base_sec_hex: &str,
) -> Result<String, JsValue> {
    let derivation = hex_to_bytes32(derivation_hex).map_err(|e| JsValue::from_str(&e))?;
    let base_sec = hex_to_bytes32(base_sec_hex).map_err(|e| JsValue::from_str(&e))?;
    Ok(bytes_to_hex(&keys::derive_secret_key_bytes(
        &derivation,
        out_index,
        &base_sec,
    )))
}

/// Maps a public key to an Edwards point: `ge_mul8(ge_fromfe(cn_fast_hash(pub)))`.
///
/// # Parameters
/// - `pub_hex` — 64-char hex (32-byte public key).
///
/// # Returns
/// 320-char hex: 160-byte `ge_p3` (`STRUCT_SIZES.GE_P3` in the web wallet).
///
/// # When to use
/// Ring signatures and other code that passes a **`ge_p3` buffer** into `ge_scalarmult`
/// (wallet `CnUtils.hash_to_ec` / `CnNativeBride.hash_to_ec`).
#[wasm_bindgen]
pub fn hash_to_ec160(pub_hex: &str) -> Result<String, JsValue> {
    let pub_key = hex_to_bytes32(pub_hex).map_err(|e| JsValue::from_str(&e))?;
    Ok(bytes_to_hex(&ffi::hash_to_ec_p3_bytes(&pub_key)))
}

/// Same curve map as [`hash_to_ec160`], but returns a **32-byte compressed** point.
///
/// # Parameters
/// - `pub_hex` — 64-char hex (32-byte public key).
///
/// # Returns
/// 64-char hex compressed Edwards point (`ge_p3_tobytes` of the internal `ge_p3`).
///
/// # When to use
/// `ge_double_scalarmult_postcomp_vartime`, key-image helpers, and any API that expects
/// a normal 32-byte point (wallet `CnNativeBride.hash_to_ec_2`).
#[wasm_bindgen]
pub fn hash_to_ec32(pub_hex: &str) -> Result<String, JsValue> {
    let pub_key = hex_to_bytes32(pub_hex).map_err(|e| JsValue::from_str(&e))?;
    Ok(bytes_to_hex(&ffi::hash_to_ec_bytes(&pub_key)))
}

/// Deprecated alias for [`hash_to_ec32`]. Prefer `hash_to_ec32` or `hash_to_ec160` explicitly.
#[wasm_bindgen]
pub fn hash_to_ec(pub_hex: &str) -> Result<String, JsValue> {
    hash_to_ec32(pub_hex)
}

/// Computes a CryptoNote key image: `sec × hash_to_ec(pub)` using the internal `ge_p3`
/// from [`hash_to_ec160`], then compresses to 32 bytes.
///
/// Port of conceal-core `crypto_ops::generate_key_image`.
/// Wallet equivalent: `CnNativeBride.generate_key_image_2(pub, sec)`.
///
/// # Parameters
/// - `pub_hex` — 64-char hex (32-byte public key).
/// - `sec_hex` — 64-char hex (32-byte secret key; must be canonical per `sc_check`).
///
/// # Returns
/// 64-char hex key image.
///
/// # Errors
/// Invalid hex length/content, or non-canonical `sec_hex`.
#[wasm_bindgen]
pub fn generate_key_image(pub_hex: &str, sec_hex: &str) -> Result<String, JsValue> {
    keys::generate_key_image_hex(pub_hex, sec_hex).map_err(|e| JsValue::from_str(&e))
}

// ---------------------------------------------------------------------------
// Signatures (crypto.cpp)
// ---------------------------------------------------------------------------

/// Standard CryptoNote signature (`c || r`), 128-char hex.
///
/// Port of `crypto::generate_signature`. `prefix_hash` is typically a transaction
/// or block hash; `pub` / `sec` must be a matching key pair.
///
/// # Parameters
/// - `prefix_hash_hex` — 64-char hex (32-byte hash).
/// - `pub_hex` — 64-char hex spend/output public key.
/// - `sec_hex` — 64-char hex secret key (canonical scalar).
///
/// # Returns
/// 128-char hex signature.
#[wasm_bindgen]
pub fn generate_signature(
    prefix_hash_hex: &str,
    pub_hex: &str,
    sec_hex: &str,
) -> Result<String, JsValue> {
    signature::generate_signature_hex(prefix_hash_hex, pub_hex, sec_hex)
        .map_err(|e| JsValue::from_str(&e))
}

/// Ring signature for one input: one 128-char hex signature per ring member.
///
/// Port of `crypto::generate_ring_signature`. `key_image` must match `sec` at
/// `sec_index` (`generate_key_image(pub, sec)`). `pubs_hex` is the ring public keys.
///
/// # Parameters
/// - `prefix_hash_hex` — 64-char hex message hash.
/// - `key_image_hex` — 64-char hex key image.
/// - `pubs_hex` — array of 64-char hex public keys (ring size = length).
/// - `sec_hex` — 64-char hex secret for the real input at `sec_index`.
/// - `sec_index` — index of the signing key in `pubs_hex`.
///
/// # Returns
/// Array of 128-char hex signatures (length = ring size).
#[wasm_bindgen]
pub fn generate_ring_signature(
    prefix_hash_hex: &str,
    key_image_hex: &str,
    pubs_hex: Vec<String>,
    sec_hex: &str,
    sec_index: u32,
) -> Result<js_sys::Array, JsValue> {
    let sigs = signature::generate_ring_signature_hex(
        prefix_hash_hex,
        key_image_hex,
        &pubs_hex,
        sec_hex,
        sec_index as usize,
    )
    .map_err(|e| JsValue::from_str(&e))?;
    let arr = js_sys::Array::new();
    for s in sigs {
        arr.push(&JsValue::from_str(&s));
    }
    Ok(arr)
}

/// Verifies a standard CryptoNote signature.
///
/// Port of `crypto::check_signature`.
#[wasm_bindgen]
pub fn check_signature(
    prefix_hash_hex: &str,
    pub_hex: &str,
    sig_hex: &str,
) -> Result<bool, JsValue> {
    signature::check_signature_hex(prefix_hash_hex, pub_hex, sig_hex)
        .map_err(|e| JsValue::from_str(&e))
}

/// Verifies a CryptoNote signature in transaction-proof mode (wallet `checkTxProof`).
///
/// Challenge binds `prefix_hash`, derivation `D`, tx public key `R`, and output key `A`
/// (`A` is not mixed into `X`/`Y`; it is accepted for API parity with the wallet).
/// Uses `Y = c·D + r·G` like `CnNativeBride.checkTxProof`. Invalid hex → `false`.
#[wasm_bindgen]
pub fn check_tx_proof(
    prefix_hash_hex: &str,
    r_pub_hex: &str,
    a_pub_hex: &str,
    d_pub_hex: &str,
    sig_hex: &str,
) -> bool {
    signature::check_tx_proof_hex(prefix_hash_hex, r_pub_hex, a_pub_hex, d_pub_hex, sig_hex)
}

/// Verifies a ring signature.
///
/// Port of `crypto::check_ring_signature`.
#[wasm_bindgen]
pub fn check_ring_signature(
    prefix_hash_hex: &str,
    key_image_hex: &str,
    pubs_hex: Vec<String>,
    sigs_hex: Vec<String>,
) -> Result<bool, JsValue> {
    signature::check_ring_signature_hex(prefix_hash_hex, key_image_hex, &pubs_hex, &sigs_hex)
        .map_err(|e| JsValue::from_str(&e))
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

/// encode_address: build a standard CCX address from spend + view public keys.
/// Matches `address.encode_address` / `pubkeys_to_string` in conceal-web-wallet.
#[wasm_bindgen]
pub fn encode_address(spend_pub_hex: &str, view_pub_hex: &str) -> Result<String, JsValue> {
    let spend_pub = hex_to_bytes32(spend_pub_hex).map_err(|e| JsValue::from_str(&e))?;
    let view_pub = hex_to_bytes32(view_pub_hex).map_err(|e| JsValue::from_str(&e))?;
    Ok(address::pubkeys_to_string(&spend_pub, &view_pub))
}

/// encode_integrated_address: build a CCX integrated address with an 8-byte payment ID.
#[wasm_bindgen]
pub fn encode_integrated_address(
    spend_pub_hex: &str,
    view_pub_hex: &str,
    payment_id_hex: &str,
) -> Result<String, JsValue> {
    let spend_pub = hex_to_bytes32(spend_pub_hex).map_err(|e| JsValue::from_str(&e))?;
    let view_pub = hex_to_bytes32(view_pub_hex).map_err(|e| JsValue::from_str(&e))?;
    let payment_id = hex_to_bytes(payment_id_hex).map_err(|e| JsValue::from_str(&e))?;
    if payment_id.len() != address::INTEGRATED_ID_SIZE {
        return Err(JsValue::from_str(&format!(
            "paymentId must be a {}-char hex string",
            address::INTEGRATED_ID_SIZE * 2
        )));
    }
    let payment_id: [u8; address::INTEGRATED_ID_SIZE] = payment_id
        .try_into()
        .map_err(|_| JsValue::from_str("paymentId must be exactly 8 bytes"))?;
    Ok(address::encode_integrated_address(
        &spend_pub,
        &view_pub,
        &payment_id,
    ))
}

/// decode_address: validate and extract spend/view public keys from an address string.
/// Returns `{ spend: hex, view: hex, intPaymentId: hex | null }`.
/// Surfaces the embedded payment ID for integrated addresses.
#[wasm_bindgen]
pub fn decode_address(address: &str) -> Result<JsValue, JsValue> {
    let decoded = address::decode_address_full(address).map_err(|e| JsValue::from_str(&e))?;
    to_js_value(&DecodedAddressJs {
        spend: bytes_to_hex(&decoded.spend),
        view: bytes_to_hex(&decoded.view),
        int_payment_id: decoded.int_payment_id.map(|id| bytes_to_hex(&id)),
    })
}
