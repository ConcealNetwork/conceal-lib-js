## Why

Wallet SDK needs a memory-hard password KDF for future `{ envelope: 3 }` encryption. conceal-lib-js should expose a low-level Argon2id primitive only — no envelopes or password policy here.

## What Changes

- Add RustCrypto Argon2id (v0x13) to the `crypto` WASM crate
- Export `crypto.argon2id(passwordHex, saltHex, memoryKiB, iterations, parallelism)` → 64 lowercase hex (32 bytes)
- Conservative wasm-safe parameter bounds covering wallet profiles 19/32/64 MiB
- Dedicated test suite + README/JSDoc; regenerate committed WASM artifacts

## Capabilities

### New Capabilities
- `argon2id-kdf`: Byte-oriented Argon2id key derivation via the existing `crypto` namespace

### Modified Capabilities

## Impact

- `rust/crypto` dependency + new wasm-bindgen export
- Regenerated `src/wasm/crypto` and `src/wasm-browser/crypto`
- `test/test-argon2id.js` + Node runner registration
- README / generated declarations
- No breaking changes to existing APIs; no secretbox / envelope work
