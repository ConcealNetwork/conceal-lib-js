//! Random bytes for signature nonces — matches `generate_random_bytes` in conceal-core.
//!
//! Native builds use the C Keccak-f stream from `conceal-rng.c` (parity with conceal-core).
//! WASM builds use `getrandom` (no libc headers in the wasm sysroot).

use std::cell::Cell;

#[cfg(not(target_arch = "wasm32"))]
use std::sync::OnceLock;

thread_local! {
    static TEST_RNG_ACTIVE: Cell<bool> = const { Cell::new(false) };
}

#[cfg(not(target_arch = "wasm32"))]
static INIT: OnceLock<()> = OnceLock::new();

#[cfg(not(target_arch = "wasm32"))]
unsafe extern "C" {
    fn conceal_rng_fill(result: *mut u8, n: usize);
    fn conceal_rng_seed_bytes(seed: *const u8, len: usize);
}

#[cfg(all(test, not(target_arch = "wasm32")))]
unsafe extern "C" {
    fn conceal_rng_seed_test();
}

#[cfg(not(target_arch = "wasm32"))]
fn ensure_seeded() {
    INIT.get_or_init(|| {
        let mut seed = [0u8; 32];
        getrandom::getrandom(&mut seed).expect("getrandom");
        unsafe {
            conceal_rng_seed_bytes(seed.as_ptr(), seed.len());
        }
    });
}

/// Fill `out` with random bytes.
pub fn fill_random_bytes(out: &mut [u8]) {
    if out.is_empty() {
        return;
    }

    #[cfg(target_arch = "wasm32")]
    {
        getrandom::getrandom(out).expect("getrandom");
    }

    #[cfg(not(target_arch = "wasm32"))]
    {
        if !TEST_RNG_ACTIVE.with(|c| c.get()) {
            ensure_seeded();
        }
        unsafe {
            conceal_rng_fill(out.as_mut_ptr(), out.len());
        }
    }
}

#[cfg(test)]
/// Deterministic RNG for unit tests (`setup_random` in conceal-core tests).
pub struct TestRng;

#[cfg(test)]
impl TestRng {
    pub fn seed(_: u8) -> Self {
        #[cfg(not(target_arch = "wasm32"))]
        unsafe {
            conceal_rng_seed_test();
        }
        TEST_RNG_ACTIVE.with(|c| c.set(true));
        TestRng
    }
}

#[cfg(test)]
impl Drop for TestRng {
    fn drop(&mut self) {
        TEST_RNG_ACTIVE.with(|c| c.set(false));
    }
}
