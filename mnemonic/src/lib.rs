mod crc32;
mod mnemonic;
mod wordlist;

use wasm_bindgen::prelude::*;

fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, String> {
    if hex.len() % 2 != 0 {
        return Err("hex string has odd length".to_string());
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect()
}

/// Generate cryptographically secure random entropy.
/// `bits` must be a multiple of 32 (typically 256).
/// Returns a hex string of length bits/4 (e.g. 64 chars for 256 bits).
#[wasm_bindgen]
pub fn mn_random(bits: u32) -> Result<String, JsValue> {
    if bits % 32 != 0 {
        return Err(JsValue::from_str(&format!("Invalid number of bits: {}", bits)));
    }
    let mut bytes = vec![0u8; (bits / 8) as usize];
    getrandom::getrandom(&mut bytes).map_err(|e| JsValue::from_str(&e.to_string()))?;
    Ok(bytes_to_hex(&bytes))
}

/// Encode a private spend key (64-char hex string) into a 25-word mnemonic.
#[wasm_bindgen]
pub fn mn_encode(hex_key: &str) -> Result<String, JsValue> {
    let bytes = hex_to_bytes(hex_key).map_err(|e| JsValue::from_str(&e))?;
    mnemonic::private_key_to_mnemonic(&bytes).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Decode a 25-word mnemonic into a private spend key (64-char hex string).
#[wasm_bindgen]
pub fn mn_decode(mnemonic: &str) -> Result<String, JsValue> {
    let bytes =
        mnemonic::mnemonic_to_private_key(mnemonic).map_err(|e| JsValue::from_str(&e.to_string()))?;
    Ok(bytes_to_hex(&bytes))
}
