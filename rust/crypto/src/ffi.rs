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

/// `ge_cached` from crypto-ops.h (4 × `fe`).
#[repr(C)]
pub struct GeCached {
    yplusx: Fe,
    yminusx: Fe,
    z: Fe,
    t2d: Fe,
}

/// `ge_dsmp` — 8 precomputed cached points for `ge_double_scalarmult_precomp_vartime`.
pub type GeDsmp = [GeCached; 8];

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
    fn conceal_ops_ge_frombytes_vartime(r: *mut GeP3, s: *const u8) -> i32;
    fn conceal_ops_ge_scalarmult_base(r: *mut GeP3, a: *const u8);
    fn conceal_ops_ge_double_scalarmult_base_vartime(
        r: *mut GeP2,
        a: *const u8,
        b: *const GeP3,
        c: *const u8,
    );
    fn conceal_ops_ge_double_scalarmult_precomp_vartime(
        r: *mut GeP2,
        a: *const u8,
        b: *const GeP3,
        c: *const u8,
        d: *const GeDsmp,
    );
    fn conceal_ops_ge_dsm_precomp(r: *mut GeDsmp, s: *const GeP3);
    fn conceal_ops_sc_reduce(s: *mut u8);
    fn conceal_ops_sc_reduce32(s: *mut u8);
    fn conceal_ops_sc_add(s: *mut u8, a: *const u8, b: *const u8);
    fn conceal_ops_sc_sub(s: *mut u8, a: *const u8, b: *const u8);
    fn conceal_ops_sc_mulsub(s: *mut u8, a: *const u8, b: *const u8, c: *const u8);
    fn conceal_ops_sc_check(s: *const u8) -> i32;
    fn conceal_ops_sc_isnonzero(s: *const u8) -> i32;
    fn conceal_ops_sc_0(s: *mut u8);
}

#[cfg(not(target_arch = "wasm32"))]
mod c_ops {
    use super::*;
    unsafe extern "C" {
        pub fn ge_fromfe_frombytes_vartime(r: *mut GeP2, s: *const u8);
        pub fn ge_mul8(r: *mut GeP1P1, t: *const GeP2);
        pub fn ge_p1p1_to_p3(r: *mut GeP3, p: *const GeP1P1);
        pub fn ge_scalarmult(r: *mut GeP2, a: *const u8, a_point: *const GeP3);
        pub fn ge_tobytes(s: *mut u8, h: *const GeP2);
        pub fn ge_p3_tobytes(s: *mut u8, h: *const GeP3);
        pub fn ge_frombytes_vartime(r: *mut GeP3, s: *const u8) -> i32;
        pub fn ge_scalarmult_base(r: *mut GeP3, a: *const u8);
        pub fn ge_double_scalarmult_base_vartime(
            r: *mut GeP2,
            a: *const u8,
            b: *const GeP3,
            c: *const u8,
        );
        pub fn ge_double_scalarmult_precomp_vartime(
            r: *mut GeP2,
            a: *const u8,
            b: *const GeP3,
            c: *const u8,
            d: *const GeDsmp,
        );
        pub fn ge_dsm_precomp(r: *mut GeDsmp, s: *const GeP3);
        pub fn sc_reduce(s: *mut u8);
        pub fn sc_reduce32(s: *mut u8);
        pub fn sc_add(s: *mut u8, a: *const u8, b: *const u8);
        pub fn sc_sub(s: *mut u8, a: *const u8, b: *const u8);
        pub fn sc_mulsub(s: *mut u8, a: *const u8, b: *const u8, c: *const u8);
        pub fn sc_check(s: *const u8) -> i32;
        pub fn sc_isnonzero(s: *const u8) -> i32;
        pub fn sc_0(s: *mut u8);
    }
}

#[inline]
unsafe fn ge_mul8_ffi(r: *mut GeP1P1, t: *const GeP2) {
    #[cfg(target_arch = "wasm32")]
    unsafe {
        conceal_ops_ge_mul8(r, t);
    }
    #[cfg(not(target_arch = "wasm32"))]
    unsafe {
        c_ops::ge_mul8(r, t);
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
        c_ops::ge_scalarmult(r, a, a_point);
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
        c_ops::ge_tobytes(s, h);
    }
}

#[inline]
unsafe fn ge_frombytes_vartime_ffi(r: *mut GeP3, s: *const u8) -> i32 {
    #[cfg(target_arch = "wasm32")]
    unsafe {
        conceal_ops_ge_frombytes_vartime(r, s)
    }
    #[cfg(not(target_arch = "wasm32"))]
    unsafe {
        c_ops::ge_frombytes_vartime(r, s)
    }
}

#[inline]
unsafe fn ge_scalarmult_base_ffi(r: *mut GeP3, a: *const u8) {
    #[cfg(target_arch = "wasm32")]
    unsafe {
        conceal_ops_ge_scalarmult_base(r, a);
    }
    #[cfg(not(target_arch = "wasm32"))]
    unsafe {
        c_ops::ge_scalarmult_base(r, a);
    }
}

#[inline]
unsafe fn ge_double_scalarmult_base_vartime_ffi(
    r: *mut GeP2,
    a: *const u8,
    b: *const GeP3,
    c: *const u8,
) {
    #[cfg(target_arch = "wasm32")]
    unsafe {
        conceal_ops_ge_double_scalarmult_base_vartime(r, a, b, c);
    }
    #[cfg(not(target_arch = "wasm32"))]
    unsafe {
        c_ops::ge_double_scalarmult_base_vartime(r, a, b, c);
    }
}

#[inline]
unsafe fn ge_double_scalarmult_precomp_vartime_ffi(
    r: *mut GeP2,
    a: *const u8,
    b: *const GeP3,
    c: *const u8,
    d: *const GeDsmp,
) {
    #[cfg(target_arch = "wasm32")]
    unsafe {
        conceal_ops_ge_double_scalarmult_precomp_vartime(r, a, b, c, d);
    }
    #[cfg(not(target_arch = "wasm32"))]
    unsafe {
        c_ops::ge_double_scalarmult_precomp_vartime(r, a, b, c, d);
    }
}

#[inline]
unsafe fn ge_dsm_precomp_ffi(r: *mut GeDsmp, s: *const GeP3) {
    #[cfg(target_arch = "wasm32")]
    unsafe {
        conceal_ops_ge_dsm_precomp(r, s);
    }
    #[cfg(not(target_arch = "wasm32"))]
    unsafe {
        c_ops::ge_dsm_precomp(r, s);
    }
}

#[inline]
unsafe fn sc_reduce_ffi(s: *mut u8) {
    #[cfg(target_arch = "wasm32")]
    unsafe {
        conceal_ops_sc_reduce(s);
    }
    #[cfg(not(target_arch = "wasm32"))]
    unsafe {
        c_ops::sc_reduce(s);
    }
}

/// `hash_to_scalar` via C `sc_reduce32` after Keccak (matches `crypto.cpp`).
pub fn hash_to_scalar_c(data: &[u8]) -> [u8; 32] {
    let hash = crate::keccak::keccak256_bytes(data);
    let mut out = hash;
    unsafe {
        sc_reduce32_ffi(out.as_mut_ptr());
    }
    out
}

pub fn sc_mulsub_c(a: &[u8; 32], b: &[u8; 32], c: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    unsafe {
        sc_mulsub_ffi(out.as_mut_ptr(), a.as_ptr(), b.as_ptr(), c.as_ptr());
    }
    out
}

pub fn sc_add_c(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    unsafe {
        sc_add_ffi(out.as_mut_ptr(), a.as_ptr(), b.as_ptr());
    }
    out
}

pub fn sc_0_c() -> [u8; 32] {
    let mut out = [0u8; 32];
    unsafe {
        sc_0_ffi(out.as_mut_ptr());
    }
    out
}

pub fn sc_isnonzero_c(s: &[u8; 32]) -> bool {
    unsafe { sc_isnonzero_ffi(s.as_ptr()) != 0 }
}

pub fn sc_check_c(s: &[u8; 32]) -> bool {
    unsafe { sc_check_ffi(s.as_ptr()) == 0 }
}

pub fn sc_sub_c(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    unsafe {
        sc_sub_ffi(out.as_mut_ptr(), a.as_ptr(), b.as_ptr());
    }
    out
}

#[inline]
unsafe fn sc_reduce32_ffi(s: *mut u8) {
    #[cfg(target_arch = "wasm32")]
    unsafe {
        conceal_ops_sc_reduce32(s);
    }
    #[cfg(not(target_arch = "wasm32"))]
    unsafe {
        c_ops::sc_reduce32(s);
    }
}

#[inline]
unsafe fn sc_add_ffi(s: *mut u8, a: *const u8, b: *const u8) {
    #[cfg(target_arch = "wasm32")]
    unsafe {
        conceal_ops_sc_add(s, a, b);
    }
    #[cfg(not(target_arch = "wasm32"))]
    unsafe {
        c_ops::sc_add(s, a, b);
    }
}

#[inline]
unsafe fn sc_sub_ffi(s: *mut u8, a: *const u8, b: *const u8) {
    #[cfg(target_arch = "wasm32")]
    unsafe {
        conceal_ops_sc_sub(s, a, b);
    }
    #[cfg(not(target_arch = "wasm32"))]
    unsafe {
        c_ops::sc_sub(s, a, b);
    }
}

#[inline]
unsafe fn sc_0_ffi(s: *mut u8) {
    #[cfg(target_arch = "wasm32")]
    unsafe {
        conceal_ops_sc_0(s);
    }
    #[cfg(not(target_arch = "wasm32"))]
    unsafe {
        c_ops::sc_0(s);
    }
}

#[inline]
unsafe fn sc_check_ffi(s: *const u8) -> i32 {
    #[cfg(target_arch = "wasm32")]
    unsafe {
        conceal_ops_sc_check(s)
    }
    #[cfg(not(target_arch = "wasm32"))]
    unsafe {
        c_ops::sc_check(s)
    }
}

#[inline]
unsafe fn sc_isnonzero_ffi(s: *const u8) -> i32 {
    #[cfg(target_arch = "wasm32")]
    unsafe {
        conceal_ops_sc_isnonzero(s)
    }
    #[cfg(not(target_arch = "wasm32"))]
    unsafe {
        c_ops::sc_isnonzero(s)
    }
}

#[inline]
unsafe fn sc_mulsub_ffi(s: *mut u8, a: *const u8, b: *const u8, c: *const u8) {
    #[cfg(target_arch = "wasm32")]
    unsafe {
        conceal_ops_sc_mulsub(s, a, b, c);
    }
    #[cfg(not(target_arch = "wasm32"))]
    unsafe {
        c_ops::sc_mulsub(s, a, b, c);
    }
}

/// Reduce 64-byte little-endian integer mod l into 32-byte scalar (`sc_reduce`).
pub fn sc_reduce_bytes(out: &mut [u8; 32], input: &[u8; 64]) {
    let mut buf = *input;
    unsafe {
        sc_reduce_ffi(buf.as_mut_ptr());
    }
    *out = buf[..32].try_into().expect("sc_reduce output");
}

pub fn ge_frombytes_vartime(point: &[u8; 32]) -> Result<GeP3, String> {
    let mut p = GeP3::zeroed();
    let rc = unsafe { ge_frombytes_vartime_ffi(&mut p, point.as_ptr()) };
    if rc != 0 {
        return Err("invalid compressed Edwards point".into());
    }
    Ok(p)
}

pub fn ge_scalarmult_base(out: &mut GeP3, scalar: &[u8; 32]) {
    unsafe {
        ge_scalarmult_base_ffi(out, scalar.as_ptr());
    }
}

pub fn ge_p3_tobytes(out: &mut [u8; 32], p: &GeP3) {
    unsafe {
        ge_p3_tobytes_ffi(out.as_mut_ptr(), p);
    }
}

pub fn ge_scalarmult(out: &mut GeP2, scalar: &[u8; 32], point: &GeP3) {
    unsafe {
        ge_scalarmult_ffi(out, scalar.as_ptr(), point);
    }
}

pub fn ge_tobytes(out: &mut [u8; 32], p: &GeP2) {
    unsafe {
        ge_tobytes_ffi(out.as_mut_ptr(), p);
    }
}

pub fn ge_double_scalarmult_base_vartime(c: &[u8; 32], p: &GeP3, r: &[u8; 32]) -> GeP2 {
    let mut out = GeP2::zeroed();
    unsafe {
        ge_double_scalarmult_base_vartime_ffi(&mut out, c.as_ptr(), p, r.as_ptr());
    }
    out
}

pub fn ge_double_scalarmult_precomp_vartime(
    r: &[u8; 32],
    p: &GeP3,
    c: &[u8; 32],
    pre: &GeDsmp,
) -> GeP2 {
    let mut out = GeP2::zeroed();
    unsafe {
        ge_double_scalarmult_precomp_vartime_ffi(&mut out, r.as_ptr(), p, c.as_ptr(), pre);
    }
    out
}

pub fn ge_dsm_precomp(p: &GeP3) -> GeDsmp {
    let mut out: GeDsmp = unsafe { std::mem::zeroed() };
    unsafe {
        ge_dsm_precomp_ffi(&mut out, p);
    }
    out
}

#[inline]
unsafe fn ge_p3_tobytes_ffi(s: *mut u8, h: *const GeP3) {
    #[cfg(target_arch = "wasm32")]
    unsafe {
        conceal_ops_ge_p3_tobytes(s, h);
    }
    #[cfg(not(target_arch = "wasm32"))]
    unsafe {
        c_ops::ge_p3_tobytes(s, h);
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

/// `hash_to_ec` in Cn.ts / `CnUtils`: raw `ge_p3` (160 bytes) for ring-signature `ge_scalarmult`.
pub fn hash_to_ec_p3_bytes(pub_key: &[u8; 32]) -> [u8; 160] {
    let p3 = hash_to_ec_p3(pub_key);
    let mut out = [0u8; 160];
    // SAFETY: `GeP3` is `#[repr(C)]` with the same layout as C `ge_p3` (4 × fe[10]).
    unsafe {
        std::ptr::copy_nonoverlapping(
            (&raw const p3).cast::<u8>(),
            out.as_mut_ptr(),
            std::mem::size_of::<GeP3>(),
        );
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
        #[cfg(target_arch = "wasm32")]
        ge_fromfe_frombytes_vartime(&mut point, h.as_ptr());
        #[cfg(not(target_arch = "wasm32"))]
        c_ops::ge_fromfe_frombytes_vartime(&mut point, h.as_ptr());
        ge_mul8_ffi(&mut point2, &point);
        #[cfg(target_arch = "wasm32")]
        ge_p1p1_to_p3(&mut res, &point2);
        #[cfg(not(target_arch = "wasm32"))]
        c_ops::ge_p1p1_to_p3(&mut res, &point2);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::{bytes_to_hex, hex_to_bytes32};

    const SPEND_PUB_HEX: &str = "1570eb695fa38fa7c395ddcb90e53e9b4d366a920e9c4b3ec988807d6f21914d";

    #[test]
    fn hash_to_ec_outputs_have_expected_sizes() {
        let pub_key = hex_to_bytes32(SPEND_PUB_HEX).unwrap();
        let p3 = hash_to_ec_p3_bytes(&pub_key);
        let compressed = hash_to_ec_bytes(&pub_key);
        assert_eq!(p3.len(), 160);
        assert_eq!(compressed.len(), 32);
        assert_eq!(bytes_to_hex(&p3).len(), 320);
        assert_eq!(bytes_to_hex(&compressed).len(), 64);
    }
}
