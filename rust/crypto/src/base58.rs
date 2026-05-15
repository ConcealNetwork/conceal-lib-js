//! CryptoNote custom Base58 encoding/decoding.
//!
//! Differs from Bitcoin Base58Check: data is split into 8-byte blocks, each
//! encoded as exactly 11 base58 characters.  The final partial block uses the
//! minimum number of characters needed to represent its value.
//!
//! Reference: conceal-web-wallet/src/lib/base58.js

const ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
/// Encoded character counts for block sizes 0–8 bytes.
const ENCODED_BLOCK_SIZES: [usize; 9] = [0, 2, 3, 5, 6, 7, 9, 10, 11];
const FULL_BLOCK_SIZE: usize = 8;
const FULL_ENCODED_BLOCK_SIZE: usize = 11;

/// Encode a block of 1–8 bytes into `ENCODED_BLOCK_SIZES[block.len()]` base58 chars.
fn encode_block(block: &[u8], out: &mut [u8]) {
    let enc_len = ENCODED_BLOCK_SIZES[block.len()];
    debug_assert_eq!(out.len(), enc_len);

    // Interpret block as a big-endian u128.
    let mut num: u128 = 0;
    for &b in block {
        num = (num << 8) | (b as u128);
    }

    // Fill from right — this produces left-padded '1' for short values.
    let mut i = enc_len as isize - 1;
    while i >= 0 {
        out[i as usize] = ALPHABET[(num % 58) as usize];
        num /= 58;
        i -= 1;
    }
}

/// Decode a block of base58 characters back to bytes.
fn decode_block(encoded: &[u8], out: &mut [u8]) -> Result<(), String> {
    let dec_len = ENCODED_BLOCK_SIZES
        .iter()
        .position(|&s| s == encoded.len())
        .ok_or_else(|| format!("invalid encoded block length: {}", encoded.len()))?;
    debug_assert_eq!(out.len(), dec_len);

    let mut num: u128 = 0;
    for &c in encoded {
        let digit = ALPHABET
            .iter()
            .position(|&b| b == c)
            .ok_or_else(|| format!("invalid base58 character: {}", c as char))?;
        num = num * 58 + digit as u128;
    }

    // Bounds check: value must fit in dec_len bytes.
    let max = 1u128 << (8 * dec_len);
    if num >= max {
        return Err("decoded value overflows block size".into());
    }

    // Store big-endian.
    for i in (0..dec_len).rev() {
        out[i] = (num & 0xFF) as u8;
        num >>= 8;
    }
    Ok(())
}

/// Encode arbitrary bytes using CryptoNote Base58.
pub fn encode(data: &[u8]) -> String {
    let full_blocks = data.len() / FULL_BLOCK_SIZE;
    let tail_len = data.len() % FULL_BLOCK_SIZE;
    let enc_tail = ENCODED_BLOCK_SIZES[tail_len];
    let total_enc = full_blocks * FULL_ENCODED_BLOCK_SIZE + enc_tail;

    let mut result = vec![ALPHABET[0]; total_enc];

    for i in 0..full_blocks {
        let block = &data[i * FULL_BLOCK_SIZE..(i + 1) * FULL_BLOCK_SIZE];
        let out_slice = &mut result[i * FULL_ENCODED_BLOCK_SIZE..(i + 1) * FULL_ENCODED_BLOCK_SIZE];
        encode_block(block, out_slice);
    }

    if tail_len > 0 {
        let block = &data[full_blocks * FULL_BLOCK_SIZE..];
        let out_offset = full_blocks * FULL_ENCODED_BLOCK_SIZE;
        let out_slice = &mut result[out_offset..out_offset + enc_tail];
        encode_block(block, out_slice);
    }

    // SAFETY: all bytes come from the ASCII alphabet slice.
    unsafe { String::from_utf8_unchecked(result) }
}

/// Decode a CryptoNote Base58 string to bytes.
pub fn decode(encoded: &str) -> Result<Vec<u8>, String> {
    let enc_bytes = encoded.as_bytes();
    let full_blocks = enc_bytes.len() / FULL_ENCODED_BLOCK_SIZE;
    let tail_enc = enc_bytes.len() % FULL_ENCODED_BLOCK_SIZE;
    let tail_dec = ENCODED_BLOCK_SIZES
        .iter()
        .position(|&s| s == tail_enc)
        .ok_or_else(|| format!("invalid encoded length: {}", enc_bytes.len()))?;

    let total_bytes = full_blocks * FULL_BLOCK_SIZE + tail_dec;
    let mut result = vec![0u8; total_bytes];

    for i in 0..full_blocks {
        let enc_block = &enc_bytes[i * FULL_ENCODED_BLOCK_SIZE..(i + 1) * FULL_ENCODED_BLOCK_SIZE];
        let out_slice = &mut result[i * FULL_BLOCK_SIZE..(i + 1) * FULL_BLOCK_SIZE];
        decode_block(enc_block, out_slice)?;
    }

    if tail_dec > 0 {
        let enc_block = &enc_bytes[full_blocks * FULL_ENCODED_BLOCK_SIZE..];
        let out_offset = full_blocks * FULL_BLOCK_SIZE;
        let out_slice = &mut result[out_offset..out_offset + tail_dec];
        decode_block(enc_block, out_slice)?;
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Encoding then decoding must return the original bytes.
    #[test]
    fn roundtrip() {
        let data: Vec<u8> = (0u8..71).collect(); // typical address length
        let enc = encode(&data);
        let dec = decode(&enc).unwrap();
        assert_eq!(dec, data);
    }

    /// Single-byte roundtrip.
    #[test]
    fn single_byte() {
        for b in 0u8..=255 {
            let enc = encode(&[b]);
            let dec = decode(&enc).unwrap();
            assert_eq!(dec, vec![b]);
        }
    }

    /// Full 8-byte block produces 11 characters.
    #[test]
    fn full_block_len() {
        let enc = encode(&[0xFFu8; 8]);
        assert_eq!(enc.len(), 11);
    }
}
