//! Builds conceal-core `crypto-ops.c` for parity with `generate_key_image` / `hash_to_ec`.

fn main() {
    let target = std::env::var("TARGET").unwrap();
    let vendor =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("vendor/conceal-core-crypto");

    println!(
        "cargo:rerun-if-changed={}",
        vendor.join("crypto-ops.c").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        vendor.join("crypto-ops-data.c").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        vendor.join("crypto-ops.h").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        vendor.join("conceal-wasm-wrap.c").display()
    );
    for name in [
        "keccak.c",
        "hash-rng.c",
        "conceal-rng.c",
        "keccak.h",
        "hash-ops-rng.h",
    ] {
        println!("cargo:rerun-if-changed={}", vendor.join(name).display());
    }
    println!(
        "cargo:rerun-if-changed={}",
        vendor.join("wasm-sysroot").display()
    );

    let mut build = cc::Build::new();
    build
        .file(vendor.join("crypto-ops-data.c"))
        .include(&vendor)
        .define("NDEBUG", None);

    if target == "wasm32-unknown-unknown" {
        // No libc headers; local stubs + renamed symbols to avoid wasm-bindgen collisions.
        // Keccak PRNG (keccak.c / conceal-rng.c) is host-only; wasm uses getrandom in rng.rs.
        build
            .include(vendor.join("wasm-sysroot"))
            .file(vendor.join("conceal-wasm-wrap.c"));
    } else {
        build
            .file(vendor.join("crypto-ops.c"))
            .file(vendor.join("keccak.c"))
            .file(vendor.join("hash-rng.c"))
            .file(vendor.join("conceal-rng.c"));
    }

    build.compile("conceal_crypto_ops");
}
