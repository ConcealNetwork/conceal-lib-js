// Ported from Mnemonics.cpp
// Copyright 2014-2018 The Monero Developers
// Copyright (c) 2018-2023 Conceal Network & Conceal Devs

use crate::crc32::crc32;
use crate::wordlist::{ENGLISH, WORD_LIST_LEN};

const WL: u32 = WORD_LIST_LEN; // 1626

#[derive(Debug, PartialEq)]
pub enum MnemonicError {
    WrongWordCount(usize),
    UnknownWord(String),
    InvalidChecksum,
    InvalidEncoding,
    InvalidKeyLength,
}

impl std::fmt::Display for MnemonicError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MnemonicError::WrongWordCount(n) => {
                write!(f, "expected 25 words, got {}", n)
            }
            MnemonicError::UnknownWord(w) => write!(f, "unknown word: {}", w),
            MnemonicError::InvalidChecksum => write!(f, "invalid checksum"),
            MnemonicError::InvalidEncoding => write!(f, "invalid word encoding"),
            MnemonicError::InvalidKeyLength => write!(f, "key must be exactly 32 bytes"),
        }
    }
}

fn find_word_index(word: &str) -> Option<u32> {
    ENGLISH
        .iter()
        .position(|&w| w == word)
        .map(|i| i as u32)
}

fn checksum_word(words: &[&str]) -> &'static str {
    let trimmed: String = words.iter().map(|w| &w[..3.min(w.len())]).collect();
    let hash = crc32(&trimmed);
    ENGLISH[(hash % words.len() as u64) as usize]
}

/// Encode a 32-byte private key into a 25-word mnemonic string.
pub fn private_key_to_mnemonic(key: &[u8]) -> Result<String, MnemonicError> {
    if key.len() != 32 {
        return Err(MnemonicError::InvalidKeyLength);
    }

    let mut words: Vec<&str> = Vec::with_capacity(25);

    for chunk in key.chunks_exact(4) {
        let val = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);

        let w1 = val % WL;
        let w2 = (val / WL + w1) % WL;
        let w3 = (val / WL / WL + w2) % WL;

        words.push(ENGLISH[w1 as usize]);
        words.push(ENGLISH[w2 as usize]);
        words.push(ENGLISH[w3 as usize]);
    }

    // 24 words generated; compute and append checksum
    let cs = checksum_word(&words);
    words.push(cs);

    Ok(words.join(" "))
}

/// Decode a 25-word mnemonic string into a 32-byte private key.
pub fn mnemonic_to_private_key(mnemonic: &str) -> Result<Vec<u8>, MnemonicError> {
    let words: Vec<&str> = mnemonic.split_whitespace().collect();

    if words.len() != 25 {
        return Err(MnemonicError::WrongWordCount(words.len()));
    }

    // Validate all words exist in the word list
    for &word in &words {
        if find_word_index(word).is_none() {
            return Err(MnemonicError::UnknownWord(word.to_string()));
        }
    }

    // Validate checksum: the 25th word must equal the derived checksum of the first 24
    let expected_cs = checksum_word(&words[..24]);
    if words[24] != expected_cs {
        return Err(MnemonicError::InvalidChecksum);
    }

    let mut key = Vec::with_capacity(32);

    for triple in words[..24].chunks_exact(3) {
        let w1 = find_word_index(triple[0]).unwrap();
        let w2 = find_word_index(triple[1]).unwrap();
        let w3 = find_word_index(triple[2]).unwrap();

        let val = w1
            + WL * ((WL - w1 + w2) % WL)
            + WL * WL * ((WL - w2 + w3) % WL);

        if val % WL != w1 {
            return Err(MnemonicError::InvalidEncoding);
        }

        key.extend_from_slice(&val.to_le_bytes());
    }

    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        // All-zero key produces a stable mnemonic; verify round-trip
        let key = vec![0u8; 32];
        let mnemonic = private_key_to_mnemonic(&key).unwrap();
        let recovered = mnemonic_to_private_key(&mnemonic).unwrap();
        assert_eq!(key, recovered);
    }

    #[test]
    fn wrong_length_key() {
        assert!(private_key_to_mnemonic(&[0u8; 31]).is_err());
    }

    #[test]
    fn wrong_word_count() {
        assert!(mnemonic_to_private_key("abbey abbey").is_err());
    }
}
