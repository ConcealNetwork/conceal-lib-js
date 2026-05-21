//! CryptoNote `generate_signature` and `generate_ring_signature` — port of
//! `conceal-core/src/crypto/crypto.cpp` (`crypto_ops`).

use crate::ffi::{
    ge_double_scalarmult_base_vartime, ge_double_scalarmult_precomp_vartime,
    ge_dsm_precomp, ge_frombytes_vartime, ge_scalarmult, ge_scalarmult_base, ge_tobytes,
    hash_to_ec_p3, GeP2, GeP3,
};
use crate::ffi::{
    hash_to_scalar_c, sc_add_c, sc_check_c, sc_isnonzero_c, sc_mulsub_c, sc_sub_c, sc_0_c,
};
use crate::scalar::sc_check_bytes;
use crate::utils::hex_to_bytes32;

const SIGNATURE_SIZE: usize = 64;

/// `s_comm` from `crypto.cpp` (prefix hash + pub + commitment point).
#[repr(C)]
struct SComm {
    h: [u8; 32],
    key: [u8; 32],
    comm: [u8; 32],
}

/// `rs_comm` header (`ab[]` follows in a variable-size buffer).
#[repr(C)]
struct RsCommHeader {
    h: [u8; 32],
}

#[repr(C)]
struct RsCommAb {
    a: [u8; 32],
    b: [u8; 32],
}

fn random_scalar() -> [u8; 32] {
    let mut tmp = [0u8; 64];
    crate::rng::fill_random_bytes(&mut tmp);
    let mut out = [0u8; 32];
    crate::ffi::sc_reduce_bytes(&mut out, &tmp);
    out
}

/// Standard CryptoNote signature: 64 bytes (`c || r`).
///
/// Ref: `crypto_ops::generate_signature` in `crypto.cpp`.
pub fn generate_signature_bytes(
    prefix_hash: &[u8; 32],
    pub_key: &[u8; 32],
    sec_key: &[u8; 32],
) -> Result<[u8; SIGNATURE_SIZE], String> {
    if !sc_check_bytes(sec_key) {
        return Err("invalid secret key: scalar is not canonical".into());
    }

    let mut sig = [0u8; SIGNATURE_SIZE];
    let k = random_scalar();
    let mut tmp3 = GeP3::zeroed();
    ge_scalarmult_base(&mut tmp3, &k);

    let mut buf = SComm {
        h: *prefix_hash,
        key: *pub_key,
        comm: [0u8; 32],
    };
    crate::ffi::ge_p3_tobytes(&mut buf.comm, &tmp3);
    let comm_bytes = unsafe {
        std::slice::from_raw_parts(
            (&raw const buf).cast::<u8>(),
            std::mem::size_of::<SComm>(),
        )
    };
    let c = hash_to_scalar_c(comm_bytes);
    sig[..32].copy_from_slice(&c);
    sig[32..].copy_from_slice(&sc_mulsub_c(&c, sec_key, &k));
    Ok(sig)
}

fn rs_comm_size(pubs_count: usize) -> usize {
    std::mem::size_of::<RsCommHeader>() + pubs_count * std::mem::size_of::<RsCommAb>()
}

/// Ring signature: `pubs_count` signatures of 64 bytes each.
///
/// Ref: `crypto_ops::generate_ring_signature` in `crypto.cpp`.
pub fn generate_ring_signature_bytes(
    prefix_hash: &[u8; 32],
    key_image: &[u8; 32],
    pubs: &[[u8; 32]],
    sec_key: &[u8; 32],
    sec_index: usize,
) -> Result<Vec<[u8; SIGNATURE_SIZE]>, String> {
    let pubs_count = pubs.len();
    if sec_index >= pubs_count {
        return Err("sec_index out of range".into());
    }
    if !sc_check_bytes(sec_key) {
        return Err("invalid secret key: scalar is not canonical".into());
    }

    let image_unp = ge_frombytes_vartime(key_image)?;
    let image_pre = ge_dsm_precomp(&image_unp);

    let mut sigs = vec![[0u8; SIGNATURE_SIZE]; pubs_count];
    let mut sum = sc_0_c();
    let mut buf = vec![0u8; rs_comm_size(pubs_count)];
    buf[..32].copy_from_slice(prefix_hash);

    let k = random_scalar();

    for i in 0..pubs_count {
        let ab_off = std::mem::size_of::<RsCommHeader>() + i * std::mem::size_of::<RsCommAb>();
        if i == sec_index {
            let mut tmp3 = GeP3::zeroed();
            ge_scalarmult_base(&mut tmp3, &k);
            let mut tmp2 = GeP2::zeroed();
            buf[ab_off..ab_off + 32].copy_from_slice(&{
                let mut a = [0u8; 32];
                crate::ffi::ge_p3_tobytes(&mut a, &tmp3);
                a
            });
            let hp = hash_to_ec_p3(&pubs[i]);
            ge_scalarmult(&mut tmp2, &k, &hp);
            {
                let mut b = [0u8; 32];
                ge_tobytes(&mut b, &tmp2);
                buf[ab_off + 32..ab_off + 64].copy_from_slice(&b);
            }
        } else {
            let mut c = [0u8; 32];
            let mut r = [0u8; 32];
            c.copy_from_slice(&random_scalar());
            r.copy_from_slice(&random_scalar());
            sigs[i][..32].copy_from_slice(&c);
            sigs[i][32..].copy_from_slice(&r);

            let tmp3 = ge_frombytes_vartime(&pubs[i])?;
            let tmp2 = ge_double_scalarmult_base_vartime(&c, &tmp3, &r);
            {
                let mut a = [0u8; 32];
                ge_tobytes(&mut a, &tmp2);
                buf[ab_off..ab_off + 32].copy_from_slice(&a);
            }

            let hp = hash_to_ec_p3(&pubs[i]);
            let tmp2 = ge_double_scalarmult_precomp_vartime(&r, &hp, &c, &image_pre);
            {
                let mut b = [0u8; 32];
                ge_tobytes(&mut b, &tmp2);
                buf[ab_off + 32..ab_off + 64].copy_from_slice(&b);
            }
            sum = sc_add_c(&sum, &c);
        }
    }

    let h = hash_to_scalar_c(&buf);
    sigs[sec_index][..32].copy_from_slice(&sc_sub_c(&h, &sum));
    let c_final: [u8; 32] = sigs[sec_index][..32].try_into().expect("sig c");
    sigs[sec_index][32..].copy_from_slice(&sc_mulsub_c(&c_final, sec_key, &k));
    Ok(sigs)
}

/// Verifies a standard signature (`check_signature` in `crypto.cpp`).
pub fn check_signature_bytes(
    prefix_hash: &[u8; 32],
    pub_key: &[u8; 32],
    sig: &[u8; SIGNATURE_SIZE],
) -> bool {
    let c_part: [u8; 32] = sig[..32].try_into().expect("sig c");
    let r_part: [u8; 32] = sig[32..].try_into().expect("sig r");
    if !sc_check_c(&c_part) || !sc_check_c(&r_part) {
        return false;
    }
    let p3 = match ge_frombytes_vartime(pub_key) {
        Ok(p) => p,
        Err(_) => return false,
    };
    let tmp2 = ge_double_scalarmult_base_vartime(&c_part, &p3, &r_part);
    let mut buf = SComm {
        h: *prefix_hash,
        key: *pub_key,
        comm: [0u8; 32],
    };
    ge_tobytes(&mut buf.comm, &tmp2);
    let c = hash_to_scalar_c(unsafe {
        std::slice::from_raw_parts(
            (&raw const buf).cast::<u8>(),
            std::mem::size_of::<SComm>(),
        )
    });
    let diff = sc_sub_c(&c, &c_part);
    !sc_isnonzero_c(&diff)
}

/// Verifies a ring signature (`check_ring_signature` in `crypto.cpp`).
pub fn check_ring_signature_bytes(
    prefix_hash: &[u8; 32],
    key_image: &[u8; 32],
    pubs: &[[u8; 32]],
    sigs: &[[u8; SIGNATURE_SIZE]],
) -> bool {
    if pubs.len() != sigs.len() || pubs.is_empty() {
        return false;
    }
    let image_unp = match ge_frombytes_vartime(key_image) {
        Ok(p) => p,
        Err(_) => return false,
    };
    let image_pre = ge_dsm_precomp(&image_unp);
    let mut sum = sc_0_c();
    let mut buf = vec![0u8; rs_comm_size(pubs.len())];
    buf[..32].copy_from_slice(prefix_hash);

    for (i, pub_key) in pubs.iter().enumerate() {
        let c_part: [u8; 32] = sigs[i][..32].try_into().expect("sig c");
        let r_part: [u8; 32] = sigs[i][32..].try_into().expect("sig r");
        if !sc_check_c(&c_part) || !sc_check_c(&r_part) {
            return false;
        }
        let p3 = match ge_frombytes_vartime(pub_key) {
            Ok(p) => p,
            Err(_) => return false,
        };
        let ab_off = std::mem::size_of::<RsCommHeader>() + i * std::mem::size_of::<RsCommAb>();
        let tmp2 = ge_double_scalarmult_base_vartime(&c_part, &p3, &r_part);
        {
            let mut a = [0u8; 32];
            ge_tobytes(&mut a, &tmp2);
            buf[ab_off..ab_off + 32].copy_from_slice(&a);
        }
        let hp = hash_to_ec_p3(pub_key);
        let tmp2 = ge_double_scalarmult_precomp_vartime(&r_part, &hp, &c_part, &image_pre);
        {
            let mut b = [0u8; 32];
            ge_tobytes(&mut b, &tmp2);
            buf[ab_off + 32..ab_off + 64].copy_from_slice(&b);
        }
        sum = sc_add_c(&sum, &c_part);
    }
    let h = hash_to_scalar_c(&buf);
    let diff = sc_sub_c(&h, &sum);
    !sc_isnonzero_c(&diff)
}

/// Hex API for `check_signature`.
pub fn check_signature_hex(
    prefix_hash_hex: &str,
    pub_hex: &str,
    sig_hex: &str,
) -> Result<bool, String> {
    let prefix_hash = hex_to_bytes32(prefix_hash_hex)?;
    let pub_key = hex_to_bytes32(pub_hex)?;
    let sig_bytes = crate::utils::hex_to_bytes(sig_hex)?;
    if sig_bytes.len() != SIGNATURE_SIZE {
        return Err(format!(
            "signature must be {} bytes, got {}",
            SIGNATURE_SIZE,
            sig_bytes.len()
        ));
    }
    let sig: [u8; SIGNATURE_SIZE] = sig_bytes.try_into().map_err(|_| "invalid signature length")?;
    Ok(check_signature_bytes(
        &prefix_hash,
        &pub_key,
        &sig,
    ))
}

/// Hex API for `check_ring_signature`.
pub fn check_ring_signature_hex(
    prefix_hash_hex: &str,
    key_image_hex: &str,
    pubs_hex: &[String],
    sigs_hex: &[String],
) -> Result<bool, String> {
    if pubs_hex.len() != sigs_hex.len() {
        return Err("pubs and signatures length mismatch".into());
    }
    let prefix_hash = hex_to_bytes32(prefix_hash_hex)?;
    let key_image = hex_to_bytes32(key_image_hex)?;
    let pubs: Result<Vec<[u8; 32]>, String> = pubs_hex.iter().map(|h| hex_to_bytes32(h)).collect();
    let pubs = pubs?;
    let mut sigs = Vec::with_capacity(sigs_hex.len());
    for sig_hex in sigs_hex {
        let bytes = crate::utils::hex_to_bytes(sig_hex)?;
        if bytes.len() != SIGNATURE_SIZE {
            return Err(format!(
                "each signature must be {} bytes, got {}",
                SIGNATURE_SIZE,
                bytes.len()
            ));
        }
        sigs.push(
            bytes
                .try_into()
                .map_err(|_| "invalid signature length".to_string())?,
        );
    }
    Ok(check_ring_signature_bytes(
        &prefix_hash,
        &key_image,
        &pubs,
        &sigs,
    ))
}

/// Hex API for `generate_signature`.
pub fn generate_signature_hex(
    prefix_hash_hex: &str,
    pub_hex: &str,
    sec_hex: &str,
) -> Result<String, String> {
    let prefix_hash = hex_to_bytes32(prefix_hash_hex)?;
    let pub_key = hex_to_bytes32(pub_hex)?;
    let sec_key = hex_to_bytes32(sec_hex)?;
    let sig = generate_signature_bytes(&prefix_hash, &pub_key, &sec_key)?;
    Ok(crate::utils::bytes_to_hex(&sig))
}

/// Hex API for `generate_ring_signature`; returns `pubs_count` concatenated 128-char hex strings
/// in a JSON array for WASM.
pub fn generate_ring_signature_hex(
    prefix_hash_hex: &str,
    key_image_hex: &str,
    pubs_hex: &[String],
    sec_hex: &str,
    sec_index: usize,
) -> Result<Vec<String>, String> {
    let prefix_hash = hex_to_bytes32(prefix_hash_hex)?;
    let key_image = hex_to_bytes32(key_image_hex)?;
    let sec_key = hex_to_bytes32(sec_hex)?;
    let pubs: Result<Vec<[u8; 32]>, String> = pubs_hex.iter().map(|h| hex_to_bytes32(h)).collect();
    let pubs = pubs?;
    let sigs = generate_ring_signature_bytes(
        &prefix_hash,
        &key_image,
        &pubs,
        &sec_key,
        sec_index,
    )?;
    Ok(sigs
        .iter()
        .map(|s| crate::utils::bytes_to_hex(s))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ffi::generate_key_image_bytes;
    use crate::keys::generate_keys_bytes;
    use crate::rng::TestRng;

    #[test]
    fn generate_and_check_signature_roundtrip() {
        let _rng = TestRng::seed(42);
        let seed = [1u8; 32];
        let (sec, pub_key) = generate_keys_bytes(&seed);
        let prefix = crate::keccak::keccak256_bytes(b"test-prefix");
        let sig = generate_signature_bytes(&prefix, &pub_key, &sec).unwrap();
        assert!(check_signature_bytes(&prefix, &pub_key, &sig));
    }

    #[test]
    fn generate_and_check_ring_signature_roundtrip() {
        let _rng = TestRng::seed(42);
        let seed = [2u8; 32];
        let (sec, pub_key) = generate_keys_bytes(&seed);
        let image = generate_key_image_bytes(&pub_key, &sec).unwrap();
        let prefix = crate::keccak::keccak256_bytes(b"ring-prefix");
        let decoy = generate_keys_bytes(&[3u8; 32]).1;
        let pubs = [decoy, pub_key];
        let sigs = generate_ring_signature_bytes(&prefix, &image, &pubs, &sec, 1).unwrap();
        assert_eq!(sigs.len(), 2);
        assert!(check_ring_signature_bytes(&prefix, &image, &pubs, &sigs));
    }

    #[test]
    fn ring_signature_matches_key_image() {
        let _rng = TestRng::seed(99);
        let seed = [7u8; 32];
        let (sec, pub_key) = generate_keys_bytes(&seed);
        let image = generate_key_image_bytes(&pub_key, &sec).unwrap();
        let prefix = [0u8; 32];
        let sigs = generate_ring_signature_bytes(&prefix, &image, &[pub_key], &sec, 0).unwrap();
        assert_eq!(sigs.len(), 1);
        assert_eq!(sigs[0].len(), 64);
        assert!(check_ring_signature_bytes(
            &prefix,
            &image,
            &[pub_key],
            &sigs
        ));
    }
}
