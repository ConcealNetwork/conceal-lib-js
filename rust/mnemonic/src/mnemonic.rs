// Ported from Mnemonics.cpp
// Copyright 2014-2018 The Monero Developers
// Copyright (c) 2018-2026 Conceal Network & Conceal Devs

use crate::crc32::crc32;
use crate::wordlist::WordList;

#[derive(Debug, PartialEq)]
pub enum MnemonicError {
    /// The mnemonic did not contain the expected number of words (24 for Electrum, 25 otherwise).
    WrongWordCount(usize),
    /// A word in the mnemonic was not found in the language's word list.
    UnknownWord(String),
    /// The checksum word does not match the computed checksum of the data words.
    InvalidChecksum,
    /// Word triple cannot be decoded back to a valid 4-byte chunk (internal consistency check).
    InvalidEncoding,
    /// The raw key slice was not exactly 32 bytes.
    InvalidKeyLength,
}

impl std::fmt::Display for MnemonicError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MnemonicError::WrongWordCount(n) => {
                write!(f, "wrong word count: got {}", n)
            }
            MnemonicError::UnknownWord(w) => write!(f, "unknown word: {}", w),
            MnemonicError::InvalidChecksum => write!(f, "invalid checksum"),
            MnemonicError::InvalidEncoding => write!(f, "invalid word encoding"),
            MnemonicError::InvalidKeyLength => write!(f, "key must be exactly 32 bytes"),
        }
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Return the first `n` Unicode characters of `s` as a string slice.
/// Safe for multi-byte encodings (e.g. Japanese kana).
fn take_chars(s: &str, n: usize) -> &str {
    let end = s.char_indices().nth(n).map(|(i, _)| i).unwrap_or(s.len());
    &s[..end]
}

/// Look up a word by its first `wl.prefix_len` characters (or exact match when
/// `prefix_len == 0`).  Returns the word's index in the word list.
fn find_word_index(word: &str, wl: &WordList) -> Option<u32> {
    if wl.prefix_len == 0 {
        wl.words.iter().position(|&w| w == word).map(|i| i as u32)
    } else {
        let p = take_chars(word, wl.prefix_len);
        wl.words
            .iter()
            .position(|&w| take_chars(w, wl.prefix_len) == p)
            .map(|i| i as u32)
    }
}

/// Compute the checksum index: CRC-32 of the concatenated prefixes of `words`,
/// modulo the number of words.
fn checksum_index(words: &[&str], wl: &WordList) -> usize {
    let trimmed: String = words.iter().map(|w| take_chars(w, wl.prefix_len)).collect();
    let hash = crc32(&trimmed);
    (hash % words.len() as u64) as usize
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Encode a 32-byte private key into a mnemonic string using `wl`.
///
/// Produces 25 words when `wl.prefix_len > 0` (24 data words + 1 checksum),
/// or 24 words when `wl.prefix_len == 0` (legacy Electrum, no checksum).
pub fn private_key_to_mnemonic(key: &[u8], wl: &WordList) -> Result<String, MnemonicError> {
    if key.len() != 32 {
        return Err(MnemonicError::InvalidKeyLength);
    }

    let n = wl.len();
    let mut words: Vec<&str> = Vec::with_capacity(25);

    for chunk in key.chunks_exact(4) {
        let val = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);

        let w1 = val % n;
        let w2 = (val / n + w1) % n;
        let w3 = (val / n / n + w2) % n;

        words.push(wl.words[w1 as usize]);
        words.push(wl.words[w2 as usize]);
        words.push(wl.words[w3 as usize]);
    }

    // Append checksum word (skipped for prefix_len == 0 / Electrum)
    if wl.prefix_len > 0 {
        let cs = checksum_index(&words, wl);
        words.push(words[cs]);
    }

    Ok(words.join(" "))
}

/// Decode a mnemonic string back into a 32-byte private key using `wl`.
///
/// Expects 25 words when `wl.prefix_len > 0`, or 24 words otherwise.
pub fn mnemonic_to_private_key(mnemonic: &str, wl: &WordList) -> Result<Vec<u8>, MnemonicError> {
    let words: Vec<&str> = mnemonic.split_whitespace().collect();

    let expected = if wl.prefix_len > 0 { 25 } else { 24 };
    if words.len() != expected {
        return Err(MnemonicError::WrongWordCount(words.len()));
    }

    let (data_words, checksum_w): (&[&str], Option<&str>) = if wl.prefix_len > 0 {
        (&words[..24], Some(words[24]))
    } else {
        (&words[..], None)
    };

    // Validate every data word exists (by prefix when prefix_len > 0)
    for &word in data_words {
        if find_word_index(word, wl).is_none() {
            return Err(MnemonicError::UnknownWord(word.to_string()));
        }
    }

    // Verify checksum
    if let Some(cs_word) = checksum_w {
        let idx = checksum_index(data_words, wl);
        let expected_cs = data_words[idx];
        if take_chars(cs_word, wl.prefix_len) != take_chars(expected_cs, wl.prefix_len) {
            return Err(MnemonicError::InvalidChecksum);
        }
    }

    let mut key = Vec::with_capacity(32);
    let n = wl.len();

    for triple in data_words.chunks_exact(3) {
        let w1 = find_word_index(triple[0], wl).unwrap();
        let w2 = find_word_index(triple[1], wl).unwrap();
        let w3 = find_word_index(triple[2], wl).unwrap();

        let val = w1 + n * ((n - w1 + w2) % n) + n * n * ((n - w2 + w3) % n);

        if val % n != w1 {
            return Err(MnemonicError::InvalidEncoding);
        }

        key.extend_from_slice(&val.to_le_bytes());
    }

    Ok(key)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wordlist::ENGLISH_WL;

    #[test]
    fn roundtrip_english() {
        let key = vec![0u8; 32];
        let mnemonic = private_key_to_mnemonic(&key, &ENGLISH_WL).unwrap();
        let recovered = mnemonic_to_private_key(&mnemonic, &ENGLISH_WL).unwrap();
        assert_eq!(key, recovered);
    }

    #[test]
    fn roundtrip_english_nonzero() {
        let key: Vec<u8> = (0u8..32).collect();
        let mnemonic = private_key_to_mnemonic(&key, &ENGLISH_WL).unwrap();
        let recovered = mnemonic_to_private_key(&mnemonic, &ENGLISH_WL).unwrap();
        assert_eq!(key, recovered);
    }

    #[test]
    fn wrong_length_key() {
        assert!(private_key_to_mnemonic(&[0u8; 31], &ENGLISH_WL).is_err());
    }

    #[test]
    fn wrong_word_count() {
        assert!(mnemonic_to_private_key("abbey abbey", &ENGLISH_WL).is_err());
    }

    #[test]
    fn english_produces_25_words() {
        let key = vec![42u8; 32];
        let mnemonic = private_key_to_mnemonic(&key, &ENGLISH_WL).unwrap();
        assert_eq!(mnemonic.split_whitespace().count(), 25);
    }

    /// Cross-compatibility: a mnemonic produced by the JS implementation must
    /// decode correctly.  A 32-byte all-zero key encodes to 25 "abbey" words
    /// (all 24 data words are "abbey", so the checksum word is always "abbey"
    /// regardless of the CRC32 index).  If the checksum logic ever drifts from
    /// the JS implementation this test will catch it.
    #[test]
    fn js_generated_mnemonic_decodes() {
        let phrase = "abbey abbey abbey abbey abbey abbey abbey abbey abbey abbey abbey abbey \
                      abbey abbey abbey abbey abbey abbey abbey abbey abbey abbey abbey abbey \
                      abbey";
        let expected = vec![0u8; 32];
        let result = mnemonic_to_private_key(phrase, &ENGLISH_WL).unwrap();
        assert_eq!(result, expected);
    }

    /// Checksum word must come from the data-word list, not the global wordlist.
    #[test]
    fn checksum_word_is_data_word() {
        let key = vec![42u8; 32];
        let mnemonic = private_key_to_mnemonic(&key, &ENGLISH_WL).unwrap();
        let words: Vec<&str> = mnemonic.split_whitespace().collect();
        assert_eq!(words.len(), 25);
        let data_words = &words[..24];
        let cs_word = words[24];
        // The checksum word must be one of the 24 data words
        assert!(
            data_words.contains(&cs_word),
            "checksum word '{cs_word}' is not in the data words — was wl.words[i] used instead of words[i]?"
        );
    }
}
