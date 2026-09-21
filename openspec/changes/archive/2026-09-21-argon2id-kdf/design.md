## Context

conceal-lib-js exposes CryptoNote primitives via Rust → WASM (`crypto` namespace) plus JS tiers. Wallet SDK needs Argon2id for future envelopes; this change adds only the KDF primitive. Existing wasm-pack targets are `bundler` and `web` with no threads.

## Goals / Non-Goals

**Goals:**
- Argon2id v0x13 via RustCrypto on the existing `crypto` WASM module
- Hex in / hex out; fixed 32-byte output
- Wasm-safe parameter caps covering wallet profiles 19/32/64 MiB
- Tests, generated declarations, README guidance (Worker for UI)

**Non-Goals:**
- Wallet envelopes, migration, password policy, biometrics
- Exactly-16-byte salt enforcement (envelope policy)
- RFC 2 GiB profile support
- WASM threads / SharedArrayBuffer / `parallel` feature
- secretbox changes; custom CryptoNight password KDF

## Decisions

1. **Crate:** `argon2` 0.6.0 with `default-features = false`, features `alloc` + `zeroize`. No `parallel`.
2. **API:** `argon2id(passwordHex, saltHex, memoryKiB, iterations, parallelism) -> String`. Internally `Params::new(..., Some(32))`.
3. **Validation table:** password 0–1024 bytes; salt 8–64; `8*p ≤ m ≤ 65536`; `1 ≤ t ≤ 64`; `1 ≤ p ≤ 4`. No reject for `m % (4p) != 0`.
4. **Export path:** Direct wasm-bindgen on `crypto`; regenerate committed WASM; JSDoc via Rust docs → generated `.d.ts`.
5. **KAT source:** RustCrypto-compatible vectors with empty secret/AD (RFC §5.3 includes secret+AD and does not match this API).

## Risks / Trade-offs

- **64 MiB wasm growth:** Large allocations may be slow/OOM on constrained browsers; document Worker usage; cap is intentional.
- **Sequential `p>1`:** Without rayon, multi-lane is correct but slower; wallets use `p=1`.
- **Independent KATs required:** Must not invent digests from the implementation under test.
