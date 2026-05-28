//! Transaction receive-output scan — one derivation + N output checks in-process.
//!
//! Used by `scan_receive_outputs` WASM export to avoid per-output JS↔WASM crossings.

use crate::keys;
use crate::utils::hex_to_bytes32;

/// Constant-time 32-byte equality.
fn bytes_eq_ct(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for i in 0..32 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

/// Derive shared key once, then check each `(out_index, on_chain_pub)` pair.
pub fn scan_receive_outputs_bytes(
    tx_pub: &[u8; 32],
    view_sec: &[u8; 32],
    spend_pub: &[u8; 32],
    output_indices: &[u32],
    output_keys: &[[u8; 32]],
) -> Result<bool, String> {
    if output_indices.len() != output_keys.len() {
        return Err(format!(
            "output_indices length {} != output_keys length {}",
            output_indices.len(),
            output_keys.len()
        ));
    }
    if output_indices.is_empty() {
        return Ok(false);
    }

    let derivation = keys::generate_key_derivation_bytes(tx_pub, view_sec)?;

    for (out_index, on_chain_key) in output_indices.iter().zip(output_keys.iter()) {
        let derived = keys::derive_public_key_bytes(&derivation, *out_index, spend_pub)?;
        if bytes_eq_ct(&derived, on_chain_key) {
            return Ok(true);
        }
    }

    Ok(false)
}

/// Hex-string wrapper for WASM and tests.
pub fn scan_receive_outputs_hex(
    tx_pub_hex: &str,
    view_sec_hex: &str,
    spend_pub_hex: &str,
    output_indices: &[u32],
    output_keys_hex: &[String],
) -> Result<bool, String> {
    if output_indices.len() != output_keys_hex.len() {
        return Err(format!(
            "output_indices length {} != output_keys_hex length {}",
            output_indices.len(),
            output_keys_hex.len()
        ));
    }

    let tx_pub = hex_to_bytes32(tx_pub_hex)?;
    let view_sec = hex_to_bytes32(view_sec_hex)?;
    let spend_pub = hex_to_bytes32(spend_pub_hex)?;

    let mut output_keys = Vec::with_capacity(output_keys_hex.len());
    for key_hex in output_keys_hex {
        output_keys.push(hex_to_bytes32(key_hex)?);
    }

    scan_receive_outputs_bytes(&tx_pub, &view_sec, &spend_pub, output_indices, &output_keys)
}

fn validate_tx_offsets(
    tx_count: usize,
    tx_offsets: &[u32],
    output_len: usize,
) -> Result<(), String> {
    if tx_offsets.len() != tx_count + 1 {
        return Err(format!(
            "tx_offsets length {} != tx count + 1 ({})",
            tx_offsets.len(),
            tx_count + 1
        ));
    }
    if tx_offsets[0] != 0 {
        return Err("tx_offsets[0] must be 0".to_string());
    }
    if tx_offsets[tx_count] as usize != output_len {
        return Err(format!(
            "tx_offsets[last] {} != output_indices length {}",
            tx_offsets[tx_count], output_len
        ));
    }
    for w in tx_offsets.windows(2) {
        if w[1] < w[0] {
            return Err("tx_offsets must be non-decreasing".to_string());
        }
    }
    Ok(())
}

/// Batch receive scan: shared view/spend keys, per-tx tx pubkey and output slice via `tx_offsets`.
///
/// `tx_offsets` has length `tx_pub_hex.len() + 1`; outputs for tx `i` are
/// `output_indices[tx_offsets[i]..tx_offsets[i+1]]` (same for keys).
/// Empty `tx_pub_hex[i]` skips derivation for that tx (returns `false`).
pub fn scan_receive_outputs_batch_hex(
    view_sec_hex: &str,
    spend_pub_hex: &str,
    tx_pub_hex: &[String],
    output_indices: &[u32],
    output_keys_hex: &[String],
    tx_offsets: &[u32],
) -> Result<Vec<bool>, String> {
    if output_indices.len() != output_keys_hex.len() {
        return Err(format!(
            "output_indices length {} != output_keys_hex length {}",
            output_indices.len(),
            output_keys_hex.len()
        ));
    }

    validate_tx_offsets(tx_pub_hex.len(), tx_offsets, output_indices.len())?;

    let view_sec = hex_to_bytes32(view_sec_hex)?;
    let spend_pub = hex_to_bytes32(spend_pub_hex)?;

    let mut output_keys = Vec::with_capacity(output_keys_hex.len());
    for key_hex in output_keys_hex {
        output_keys.push(hex_to_bytes32(key_hex)?);
    }

    let mut results = Vec::with_capacity(tx_pub_hex.len());
    for (i, tx_pub_h) in tx_pub_hex.iter().enumerate() {
        let start = tx_offsets[i] as usize;
        let end = tx_offsets[i + 1] as usize;
        let slice_indices = &output_indices[start..end];
        let slice_keys = &output_keys[start..end];

        if tx_pub_h.is_empty() {
            results.push(false);
            continue;
        }

        let tx_pub = hex_to_bytes32(tx_pub_h)?;
        let found =
            scan_receive_outputs_bytes(&tx_pub, &view_sec, &spend_pub, slice_indices, slice_keys)?;
        results.push(found);
    }

    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{
        derive_public_key_bytes, generate_key_derivation_bytes, generate_keys_bytes,
    };
    use crate::utils::bytes_to_hex;

    #[test]
    fn scan_receive_match_single_output() {
        let seed = [1u8; 32];
        let (view_sec, view_pub) = generate_keys_bytes(&seed);
        let spend_seed = [2u8; 32];
        let (spend_sec, spend_pub) = generate_keys_bytes(&spend_seed);

        let derivation = generate_key_derivation_bytes(&view_pub, &spend_sec).expect("derivation");
        let derived = derive_public_key_bytes(&derivation, 0, &spend_pub).expect("derive");

        let found = scan_receive_outputs_bytes(&view_pub, &spend_sec, &spend_pub, &[0], &[derived])
            .expect("scan");

        assert!(found);
        let _ = bytes_to_hex(&view_sec);
    }

    #[test]
    fn scan_receive_no_match() {
        let seed = [3u8; 32];
        let (_view_sec, view_pub) = generate_keys_bytes(&seed);
        let spend_seed = [4u8; 32];
        let (spend_sec, spend_pub) = generate_keys_bytes(&spend_seed);
        let wrong_key = [0u8; 32];

        let found =
            scan_receive_outputs_bytes(&view_pub, &spend_sec, &spend_pub, &[0], &[wrong_key])
                .expect("scan");

        assert!(!found);
    }

    #[test]
    fn scan_receive_empty_outputs() {
        let seed = [5u8; 32];
        let (_view_sec, view_pub) = generate_keys_bytes(&seed);
        let spend_seed = [6u8; 32];
        let (spend_sec, spend_pub) = generate_keys_bytes(&spend_seed);

        let found =
            scan_receive_outputs_bytes(&view_pub, &spend_sec, &spend_pub, &[], &[]).expect("scan");

        assert!(!found);
    }

    #[test]
    fn scan_receive_length_mismatch() {
        let seed = [7u8; 32];
        let (_view_sec, view_pub) = generate_keys_bytes(&seed);
        let spend_seed = [8u8; 32];
        let (spend_sec, spend_pub) = generate_keys_bytes(&spend_seed);

        let err = scan_receive_outputs_bytes(&view_pub, &spend_sec, &spend_pub, &[0], &[])
            .expect_err("expected mismatch in bytes path when lengths differ");

        assert!(err.contains("length"));
    }

    #[test]
    fn scan_receive_multi_index() {
        let seed = [9u8; 32];
        let (_view_sec, view_pub) = generate_keys_bytes(&seed);
        let spend_seed = [10u8; 32];
        let (spend_sec, spend_pub) = generate_keys_bytes(&spend_seed);

        let derivation = generate_key_derivation_bytes(&view_pub, &spend_sec).expect("derivation");
        let key0 = derive_public_key_bytes(&derivation, 0, &spend_pub).expect("d0");
        let key2 = derive_public_key_bytes(&derivation, 2, &spend_pub).expect("d2");
        let wrong = derive_public_key_bytes(&derivation, 1, &spend_pub).expect("d1");

        let found =
            scan_receive_outputs_bytes(&view_pub, &spend_sec, &spend_pub, &[0, 2], &[wrong, key2])
                .expect("scan");

        assert!(found);

        let found_first =
            scan_receive_outputs_bytes(&view_pub, &spend_sec, &spend_pub, &[0], &[key0])
                .expect("scan");

        assert!(found_first);
    }

    #[test]
    fn scan_receive_batch_two_txs() {
        let seed = [11u8; 32];
        let (_tx_view_sec, tx_pub) = generate_keys_bytes(&seed);
        let wallet_seed = [12u8; 32];
        let (wallet_view_sec, _wallet_view_pub) = generate_keys_bytes(&wallet_seed);
        let spend_seed = [13u8; 32];
        let (_spend_sec, spend_pub) = generate_keys_bytes(&spend_seed);

        let derivation =
            generate_key_derivation_bytes(&tx_pub, &wallet_view_sec).expect("derivation");
        let key0 = derive_public_key_bytes(&derivation, 0, &spend_pub).expect("d0");

        let view_sec_hex = bytes_to_hex(&wallet_view_sec);
        let spend_pub_hex = bytes_to_hex(&spend_pub);
        let tx_pub_hex = bytes_to_hex(&tx_pub);

        let results = scan_receive_outputs_batch_hex(
            &view_sec_hex,
            &spend_pub_hex,
            &[tx_pub_hex.clone(), String::new()],
            &[0],
            &[bytes_to_hex(&key0)],
            &[0, 1, 1],
        )
        .expect("batch");

        assert_eq!(results, vec![true, false]);
    }

    #[test]
    fn scan_receive_batch_bad_offsets() {
        let err = scan_receive_outputs_batch_hex(
            &"00".repeat(64),
            &"00".repeat(64),
            &[String::new()],
            &[],
            &[],
            &[0],
        )
        .expect_err("expected length mismatch on offsets");

        assert!(err.contains("tx_offsets"));
    }
}
