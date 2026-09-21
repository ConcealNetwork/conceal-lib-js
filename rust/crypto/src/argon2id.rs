//! Argon2id key derivation (RFC 9106) for the `crypto` WASM surface.

use argon2::{Algorithm, Argon2, Params, Version};
use wasm_bindgen::prelude::*;
use zeroize::Zeroize;

use crate::utils::{bytes_to_hex, hex_to_bytes};

/// Maximum decoded password length (DoS bound; RFC allows far more).
pub const MAX_PASSWORD_LEN: usize = 1024;
/// Minimum decoded salt length (Argon2 / RFC minimum).
pub const MIN_SALT_LEN: usize = 8;
/// Maximum decoded salt length (DoS bound).
pub const MAX_SALT_LEN: usize = 64;
/// Maximum memory cost in KiB (wasm policy; covers wallet 19/32/64 MiB profiles).
pub const MAX_MEMORY_KIB: u32 = 65_536;
/// Maximum time cost (iterations).
pub const MAX_TIME_COST: u32 = 64;
/// Maximum parallelism (lanes); wallet uses 1, RFC-style KATs use up to 4.
pub const MAX_PARALLELISM: u32 = 4;
/// Fixed derived-key length in bytes.
pub const OUTPUT_LEN: usize = 32;

/// Core Argon2id derivation (testable on native without `JsValue`).
pub(crate) fn argon2id_hex(
    password_hex: &str,
    salt_hex: &str,
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
) -> Result<String, String> {
    let mut password = hex_to_bytes(password_hex)?;
    let mut salt = hex_to_bytes(salt_hex)?;

    let result = (|| -> Result<String, String> {
        if password.len() > MAX_PASSWORD_LEN {
            return Err(format!(
                "password too long: {} bytes (max {MAX_PASSWORD_LEN})",
                password.len()
            ));
        }
        if salt.len() < MIN_SALT_LEN {
            return Err(format!(
                "salt too short: {} bytes (min {MIN_SALT_LEN})",
                salt.len()
            ));
        }
        if salt.len() > MAX_SALT_LEN {
            return Err(format!(
                "salt too long: {} bytes (max {MAX_SALT_LEN})",
                salt.len()
            ));
        }

        if parallelism < 1 || parallelism > MAX_PARALLELISM {
            return Err(format!(
                "invalid parallelism: {parallelism} (allowed 1..={MAX_PARALLELISM})"
            ));
        }
        if iterations < 1 || iterations > MAX_TIME_COST {
            return Err(format!(
                "invalid iterations: {iterations} (allowed 1..={MAX_TIME_COST})"
            ));
        }

        let min_m = parallelism
            .checked_mul(8)
            .ok_or_else(|| "parallelism overflow computing minimum memory".to_string())?;
        if memory_kib < min_m || memory_kib > MAX_MEMORY_KIB {
            return Err(format!(
                "invalid memory_kib: {memory_kib} (allowed {min_m}..={MAX_MEMORY_KIB} for p={parallelism})"
            ));
        }

        let params = Params::new(memory_kib, iterations, parallelism, Some(OUTPUT_LEN))
            .map_err(|e| format!("invalid Argon2 params: {e}"))?;
        let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

        let mut out = [0u8; OUTPUT_LEN];
        argon
            .hash_password_into(&password, &salt, &mut out)
            .map_err(|e| format!("Argon2id failed: {e}"))?;

        let hex = bytes_to_hex(&out);
        out.zeroize();
        Ok(hex)
    })();

    password.zeroize();
    salt.zeroize();
    result
}

/// Derive a 32-byte key with Argon2id v0x13 (Argon2 v1.3).
///
/// Low-level **byte-oriented** primitive: `password_hex` and `salt_hex` are
/// hex encodings of raw bytes. UTF-8 encoding of passwords is the caller's
/// responsibility (avoids Unicode ambiguity inside the library).
///
/// - `memory_kib` — memory cost in **kibibytes** (KiB)
/// - `iterations` — time cost (passes)
/// - `parallelism` — lane count (`p`); without WASM threads, lanes run sequentially
///
/// Returns 64 lowercase hex characters (32 bytes). Does not accept a variable
/// output length.
///
/// Memory-hard; when invoked from a UI thread, run in a Worker (or equivalent
/// background context). Does not require SharedArrayBuffer or WASM threads.
///
/// # Errors
///
/// Malformed hex, out-of-range parameters, or Argon2 failures. Parameters are
/// never silently clamped.
///
/// # See also
///
/// - [RFC 9106](https://www.rfc-editor.org/rfc/rfc9106.html)
/// - Project README (Argon2id / Worker guidance)
#[wasm_bindgen]
pub fn argon2id(
    password_hex: &str,
    salt_hex: &str,
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
) -> Result<String, JsValue> {
    argon2id_hex(password_hex, salt_hex, memory_kib, iterations, parallelism)
        .map_err(|e| JsValue::from_str(&e))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex_ascii(s: &str) -> String {
        bytes_to_hex(s.as_bytes())
    }

    /// Independent KATs from published PHC encodings (password=`password`, salt=`somesalt`):
    /// mudge/argon2id README (`$argon2id$v=19$m=256,t=2,p=1$c29tZXNhbHQ$…`) and
    /// tarantool/argon2 README (`m=4096,t=3,p=1`).
    #[test]
    fn kat_password_somesalt_m256_t2_p1() {
        let got = argon2id_hex(&hex_ascii("password"), &hex_ascii("somesalt"), 256, 2, 1)
            .expect("derive");
        assert_eq!(
            got,
            "9dfeb910e80bad0311fee20f9c0e2b12c17987b4cac90c2ef54d5b3021c68bfe"
        );
    }

    #[test]
    fn kat_password_somesalt_m4096_t3_p1() {
        let got = argon2id_hex(&hex_ascii("password"), &hex_ascii("somesalt"), 4096, 3, 1)
            .expect("derive");
        assert_eq!(
            got,
            "a8b9a5e5c6ea1403ba63154786b4811cfd1459dc6b23190d70cf1a317ddb9735"
        );
    }

    #[test]
    fn rejects_short_salt() {
        let err = argon2id_hex("00", "00112233445566", 256, 2, 1).unwrap_err();
        assert!(err.contains("salt too short"), "{err}");
    }

    #[test]
    fn rejects_memory_below_8p() {
        let err =
            argon2id_hex(&hex_ascii("password"), &hex_ascii("somesalt"), 7, 2, 1).unwrap_err();
        assert!(err.contains("invalid memory_kib"), "{err}");
    }
}
