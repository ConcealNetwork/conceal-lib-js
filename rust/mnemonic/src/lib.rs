//! Mnemonic encode/decode for Conceal Network private spend keys.
//!
//! Exposes three WebAssembly functions:
//!
//! | Function | Purpose |
//! |---|---|
//! | [`mn_random`] | Generate cryptographically secure random entropy (hex string) |
//! | [`mn_encode`] | Encode a 32-byte private spend key (hex) into a 25-word mnemonic |
//! | [`mn_decode`] | Decode a 25-word mnemonic back into a private spend key (hex) |
//!
//! Supported languages: `english`, `spanish`, `portuguese`, `japanese`, `electrum`.
//!
//! Ported from `Mnemonics.cpp` — Copyright 2014-2018 The Monero Developers,
//! Copyright (c) 2018-2026 Conceal Network & Conceal Devs.

mod crc32;
mod mnemonic;
mod wordlist;

use wasm_bindgen::prelude::*;

fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, String> {
    if !hex.len().is_multiple_of(2) {
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
    if !bits.is_multiple_of(32) {
        return Err(JsValue::from_str(&format!(
            "Invalid number of bits: {}",
            bits
        )));
    }
    let mut bytes = vec![0u8; (bits / 8) as usize];
    getrandom::getrandom(&mut bytes).map_err(|e| JsValue::from_str(&e.to_string()))?;
    Ok(bytes_to_hex(&bytes))
}

/// Encode a private spend key (64-char hex string) into a mnemonic.
///
/// `language` must be one of: "english", "spanish", "portuguese", "japanese",
/// "electrum".  Defaults to "english" if an empty string is passed.
#[wasm_bindgen]
pub fn mn_encode(hex_key: &str, language: &str) -> Result<String, JsValue> {
    let lang = if language.is_empty() {
        "english"
    } else {
        language
    };
    let wl = wordlist::get_wordlist(lang)
        .ok_or_else(|| JsValue::from_str(&format!("unknown language: {}", lang)))?;
    let bytes = hex_to_bytes(hex_key).map_err(|e| JsValue::from_str(&e))?;
    mnemonic::private_key_to_mnemonic(&bytes, wl).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Return the number of words in a language's word list.
/// Useful for verifying that a word list has been fully populated (expected: 1626).
#[wasm_bindgen]
pub fn mn_wordlist_len(language: &str) -> Result<u32, JsValue> {
    let wl = wordlist::get_wordlist(language)
        .ok_or_else(|| JsValue::from_str(&format!("unknown language: {}", language)))?;
    Ok(wl.len())
}

/// Decode a mnemonic back into a private spend key (64-char hex string).
///
/// `language` must match the language used during encoding.
/// Defaults to "english" if an empty string is passed.
#[wasm_bindgen]
pub fn mn_decode(mnemonic_str: &str, language: &str) -> Result<String, JsValue> {
    let lang = if language.is_empty() {
        "english"
    } else {
        language
    };
    let wl = wordlist::get_wordlist(lang)
        .ok_or_else(|| JsValue::from_str(&format!("unknown language: {}", lang)))?;
    let bytes = mnemonic::mnemonic_to_private_key(mnemonic_str, wl)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    Ok(bytes_to_hex(&bytes))
}
