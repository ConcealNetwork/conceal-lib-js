## 1. Rust Argon2id primitive

- [x] 1.1 Add `argon2` 0.6.0 (`alloc`, `zeroize`; no `parallel`) to `rust/crypto/Cargo.toml`
- [x] 1.2 Implement `argon2id` wasm-bindgen export with hex I/O, fixed 32-byte output, validation table, and buffer clearing
- [x] 1.3 Document public API with `///` (units, RFC 9106, Worker note, `@see`)

## 2. Build artifacts and package surface

- [x] 2.1 Rebuild crypto WASM for bundler + browser targets (`npm run build:crypto` / `build:browser:crypto`)
- [x] 2.2 Confirm `crypto.argon2id` appears in generated JS/`.d.ts` for both targets; no hand-duplicated generated types
- [x] 2.3 Update README with concise Argon2id docs (KiB memory, 32-byte output, Worker guidance, RFC 9106)

## 3. Tests

- [x] 3.1 Add `test/test-argon2id.js` with independent KAT, salt diversity, binary password bytes, malformed hex, invalid salt/params, and export checks
- [x] 3.2 Register the suite in `test/run-node.mjs` (and browser harness list if applicable)
- [x] 3.3 Run quality gate: `npm run types && npm run lint && npm test`
