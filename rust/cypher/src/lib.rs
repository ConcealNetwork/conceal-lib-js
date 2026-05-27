//! ChaCha stream ciphers for Conceal Network, compiled to WebAssembly.
//!
//! Provides ChaCha8, ChaCha12, and ChaCha20 using
//! the IETF nonce format:
//!   - key   : 32 bytes
//!   - nonce : 12 bytes
//!   - counter: 32-bit, starts at 0
//!
//! These are symmetric stream ciphers — encrypt and decrypt are identical
//! operations (XOR with the keystream).
//!
//! Reference: chacha8.h / chacha8.cpp in conceal-core/src/crypto/

use chacha20::cipher::{KeyIvInit, StreamCipher};
use wasm_bindgen::prelude::*;

// ---------------------------------------------------------------------------
// Pure inner functions (testable on native targets)
// ---------------------------------------------------------------------------

fn chacha8_inner(key: &[u8], nonce: &[u8], data: &[u8]) -> Result<Vec<u8>, String> {
    if key.len() != 32 {
        return Err(format!("chacha8: key must be 32 bytes, got {}", key.len()));
    }
    if nonce.len() != 12 {
        return Err(format!(
            "chacha8: nonce must be 12 bytes, got {}",
            nonce.len()
        ));
    }
    let key_arr: &[u8; 32] = key.try_into().unwrap();
    let nonce_arr: &[u8; 12] = nonce.try_into().unwrap();
    let mut cipher = chacha20::ChaCha8::new(key_arr.into(), nonce_arr.into());
    let mut buf = data.to_vec();
    cipher.apply_keystream(&mut buf);
    Ok(buf)
}

fn chacha12_inner(key: &[u8], nonce: &[u8], data: &[u8]) -> Result<Vec<u8>, String> {
    if key.len() != 32 {
        return Err(format!("chacha12: key must be 32 bytes, got {}", key.len()));
    }
    if nonce.len() != 12 {
        return Err(format!(
            "chacha12: nonce must be 12 bytes, got {}",
            nonce.len()
        ));
    }
    let key_arr: &[u8; 32] = key.try_into().unwrap();
    let nonce_arr: &[u8; 12] = nonce.try_into().unwrap();
    let mut cipher = chacha20::ChaCha12::new(key_arr.into(), nonce_arr.into());
    let mut buf = data.to_vec();
    cipher.apply_keystream(&mut buf);
    Ok(buf)
}

fn chacha20_inner(key: &[u8], nonce: &[u8], data: &[u8]) -> Result<Vec<u8>, String> {
    if key.len() != 32 {
        return Err(format!("chacha20: key must be 32 bytes, got {}", key.len()));
    }
    if nonce.len() != 12 {
        return Err(format!(
            "chacha20: nonce must be 12 bytes, got {}",
            nonce.len()
        ));
    }
    let key_arr: &[u8; 32] = key.try_into().unwrap();
    let nonce_arr: &[u8; 12] = nonce.try_into().unwrap();
    let mut cipher = chacha20::ChaCha20::new(key_arr.into(), nonce_arr.into());
    let mut buf = data.to_vec();
    cipher.apply_keystream(&mut buf);
    Ok(buf)
}

// ---------------------------------------------------------------------------
// WASM exports
// ---------------------------------------------------------------------------

/// ChaCha8 stream cipher (8 rounds).
///
/// Encrypts or decrypts `data` using `key` (32 bytes) and `nonce` (12 bytes).
/// Returns ciphertext/plaintext or an error if sizes are wrong.
#[wasm_bindgen]
pub fn chacha8(key: &[u8], nonce: &[u8], data: &[u8]) -> Result<Vec<u8>, JsValue> {
    chacha8_inner(key, nonce, data).map_err(|e| JsValue::from_str(&e))
}

/// ChaCha12 stream cipher (12 rounds).
///
/// Same interface as `chacha8` but with 12 rounds.
#[wasm_bindgen]
pub fn chacha12(key: &[u8], nonce: &[u8], data: &[u8]) -> Result<Vec<u8>, JsValue> {
    chacha12_inner(key, nonce, data).map_err(|e| JsValue::from_str(&e))
}

/// ChaCha20 stream cipher (20 rounds, IETF variant).
///
/// Same interface as `chacha8` and `chacha12`.
#[wasm_bindgen]
pub fn chacha20(key: &[u8], nonce: &[u8], data: &[u8]) -> Result<Vec<u8>, JsValue> {
    chacha20_inner(key, nonce, data).map_err(|e| JsValue::from_str(&e))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_key() -> Vec<u8> {
        (0u8..32).collect()
    }

    fn make_nonce() -> Vec<u8> {
        (0u8..12).collect()
    }

    #[test]
    fn chacha8_encrypt_decrypt_roundtrip() {
        let key = make_key();
        let nonce = make_nonce();
        let plaintext = b"hello conceal world!";
        let ciphertext = chacha8_inner(&key, &nonce, plaintext).unwrap();
        assert_ne!(ciphertext.as_slice(), plaintext.as_slice());
        let recovered = chacha8_inner(&key, &nonce, &ciphertext).unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn chacha12_encrypt_decrypt_roundtrip() {
        let key = make_key();
        let nonce = make_nonce();
        let plaintext = b"hello conceal world!";
        let ciphertext = chacha12_inner(&key, &nonce, plaintext).unwrap();
        assert_ne!(ciphertext.as_slice(), plaintext.as_slice());
        let recovered = chacha12_inner(&key, &nonce, &ciphertext).unwrap();
        assert_eq!(recovered, plaintext);
    }


    #[test]
    fn chacha20_encrypt_decrypt_roundtrip() {
        let key = make_key();
        let nonce = make_nonce();
        let plaintext = b"hello conceal world!";
        let ciphertext = chacha20_inner(&key, &nonce, plaintext).unwrap();
        assert_ne!(ciphertext.as_slice(), plaintext.as_slice());
        let recovered = chacha20_inner(&key, &nonce, &ciphertext).unwrap();
        assert_eq!(recovered, plaintext);
    }
    
    #[test]
    fn chacha8_wrong_key_size_returns_error() {
        assert!(chacha8_inner(&[0u8; 16], &[0u8; 12], b"data").is_err());
    }

    #[test]
    fn chacha8_wrong_nonce_size_returns_error() {
        assert!(chacha8_inner(&[0u8; 32], &[0u8; 8], b"data").is_err());
    }

    #[test]
    fn chacha12_differs_from_chacha8() {
        let key = make_key();
        let nonce = make_nonce();
        let data = b"test data for cipher comparison";
        let c8 = chacha8_inner(&key, &nonce, data).unwrap();
        let c12 = chacha12_inner(&key, &nonce, data).unwrap();
        assert_ne!(
            c8, c12,
            "ChaCha8 and ChaCha12 must produce different keystreams"
        );
    }

    #[test]
    fn chacha20_differs_from_chacha12() {
        let key = make_key();
        let nonce = make_nonce();
        let data = b"test data for cipher comparison";
        let c12 = chacha12_inner(&key, &nonce, data).unwrap();
        let c20 = chacha20_inner(&key, &nonce, data).unwrap();
        assert_ne!(
            c12, c20,
            "ChaCha12 and ChaCha20 must produce different keystreams"
        );
    }

    #[test]
    fn chacha20_wrong_key_size_returns_error() {
        assert!(chacha20_inner(&[0u8; 16], &[0u8; 12], b"data").is_err());
    }

    #[test]
    fn chacha20_wrong_nonce_size_returns_error() {
        assert!(chacha20_inner(&[0u8; 32], &[0u8; 8], b"data").is_err());
    }

    /// Known-vector: ChaCha8 with all-zero key/nonce must produce a non-zero keystream.
    /// The first byte is checked against the expected value from the `chacha20` crate.
    #[test]
    fn chacha8_known_vector_zero_key_nonce() {
        let key = vec![0u8; 32];
        let nonce = vec![0u8; 12];
        let data = vec![0u8; 64];
        let ks = chacha8_inner(&key, &nonce, &data).unwrap();
        assert!(!ks.iter().all(|&b| b == 0), "keystream must not be zero");
        // First byte of ChaCha8 keystream for zero key/nonce verified against chacha20 crate.
        assert_eq!(ks[0], 0x3e);
    }
}
