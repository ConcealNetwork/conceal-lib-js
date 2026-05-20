//! FFI to conceal-core `crypto-ops.c` (Ed25519 / CryptoNote group ops).
//!
//! Used for `hash_to_ec` and `generate_key_image`, which must match
//! `conceal-core/src/crypto/crypto.cpp` exactly.

/// Field element (`fe`) from crypto-ops.h.
type Fe = [i32; 10];

#[repr(C)]
pub struct GeP2 {
    x: Fe,
    y: Fe,
    z: Fe,
}

#[repr(C)]
pub struct GeP3 {
    x: Fe,
    y: Fe,
    z: Fe,
    t: Fe,
}

#[repr(C)]
pub struct GeP1P1 {
    x: Fe,
    y: Fe,
    z: Fe,
    t: Fe,
}

impl GeP2 {
    pub fn zeroed() -> Self {
        unsafe { std::mem::zeroed() }
    }
}

impl GeP3 {
    pub fn zeroed() -> Self {
        unsafe { std::mem::zeroed() }
    }
}

impl GeP1P1 {
    pub fn zeroed() -> Self {
        unsafe { std::mem::zeroed() }
    }
}

#[cfg(target_arch = "wasm32")]
unsafe extern "C" {
    fn ge_fromfe_frombytes_vartime(r: *mut GeP2, s: *const u8);
    fn conceal_ops_ge_mul8(r: *mut GeP1P1, t: *const GeP2);
    fn ge_p1p1_to_p3(r: *mut GeP3, p: *const GeP1P1);
    fn conceal_ops_ge_scalarmult(r: *mut GeP2, a: *const u8, a_point: *const GeP3);
    fn conceal_ops_ge_tobytes(s: *mut u8, h: *const GeP2);
    fn conceal_ops_ge_p3_tobytes(s: *mut u8, h: *const GeP3);
}

#[cfg(not(target_arch = "wasm32"))]
unsafe extern "C" {
    fn ge_fromfe_frombytes_vartime(r: *mut GeP2, s: *const u8);
    fn ge_mul8(r: *mut GeP1P1, t: *const GeP2);
    fn ge_p1p1_to_p3(r: *mut GeP3, p: *const GeP1P1);
    fn ge_scalarmult(r: *mut GeP2, a: *const u8, a_point: *const GeP3);
    fn ge_tobytes(s: *mut u8, h: *const GeP2);
    fn ge_p3_tobytes(s: *mut u8, h: *const GeP3);
}

#[inline]
unsafe fn ge_mul8_ffi(r: *mut GeP1P1, t: *const GeP2) {
    #[cfg(target_arch = "wasm32")]
    unsafe {
        conceal_ops_ge_mul8(r, t);
    }
    #[cfg(not(target_arch = "wasm32"))]
    unsafe {
        ge_mul8(r, t);
    }
}

#[inline]
unsafe fn ge_scalarmult_ffi(r: *mut GeP2, a: *const u8, a_point: *const GeP3) {
    #[cfg(target_arch = "wasm32")]
    unsafe {
        conceal_ops_ge_scalarmult(r, a, a_point);
    }
    #[cfg(not(target_arch = "wasm32"))]
    unsafe {
        ge_scalarmult(r, a, a_point);
    }
}

#[inline]
unsafe fn ge_tobytes_ffi(s: *mut u8, h: *const GeP2) {
    #[cfg(target_arch = "wasm32")]
    unsafe {
        conceal_ops_ge_tobytes(s, h);
    }
    #[cfg(not(target_arch = "wasm32"))]
    unsafe {
        ge_tobytes(s, h);
    }
}

#[inline]
unsafe fn ge_p3_tobytes_ffi(s: *mut u8, h: *const GeP3) {
    #[cfg(target_arch = "wasm32")]
    unsafe {
        conceal_ops_ge_p3_tobytes(s, h);
    }
    #[cfg(not(target_arch = "wasm32"))]
    unsafe {
        ge_p3_tobytes(s, h);
    }
}

/// `hash_to_ec_2` in Cn.ts: 32-byte compressed point from a public key.
pub fn hash_to_ec_bytes(pub_key: &[u8; 32]) -> [u8; 32] {
    let p3 = hash_to_ec_p3(pub_key);
    let mut out = [0u8; 32];
    unsafe {
        ge_p3_tobytes_ffi(out.as_mut_ptr(), &p3);
    }
    out
}

/// `hash_to_ec` from conceal-core `crypto.cpp` (cn_fast_hash → ge_fromfe → ge_mul8).
pub fn hash_to_ec_p3(pub_key: &[u8; 32]) -> GeP3 {
    let h = crate::keccak::keccak256_bytes(pub_key);
    let mut point = GeP2::zeroed();
    let mut point2 = GeP1P1::zeroed();
    let mut res = GeP3::zeroed();
    unsafe {
        ge_fromfe_frombytes_vartime(&mut point, h.as_ptr());
        ge_mul8_ffi(&mut point2, &point);
        ge_p1p1_to_p3(&mut res, &point2);
    }
    res
}

/// `generate_key_image` from conceal-core `crypto.cpp`.
pub fn generate_key_image_bytes(
    pub_key: &[u8; 32],
    sec_key: &[u8; 32],
) -> Result<[u8; 32], String> {
    if !crate::scalar::sc_check_bytes(sec_key) {
        return Err("invalid secret key: scalar is not canonical".into());
    }
    let point = hash_to_ec_p3(pub_key);
    let mut point2 = GeP2::zeroed();
    let mut image = [0u8; 32];
    unsafe {
        ge_scalarmult_ffi(&mut point2, sec_key.as_ptr(), &point);
        ge_tobytes_ffi(image.as_mut_ptr(), &point2);
    }
    Ok(image)
}
