/**
 * @module concealjs
 *
 * One-stop cryptographic library for Conceal Network.
 *
 * Three namespaces are exported:
 *
 * - **`mnemonic`** — `mn_encode`, `mn_decode`, `mn_random` (plain JS, no WASM).
 *   ~2.8× faster than the Rust WASM build for string-heavy mnemonic operations.
 *
 * - **`crypto`** — Keccak-256, EC scalar/point operations, key derivation,
 *   and address encoding/decoding.  All functions match the names used in
 *   `conceal-web-wallet/src/model/Cn.ts`.  Compiled from Rust to WASM.
 *
 * - **`cypher`** — ChaCha8 and ChaCha12 stream ciphers (32-byte key,
 *   12-byte nonce).  Compiled from Rust to WASM.
 *
 * ## Runtimes
 *
 * - **Node / Vite / Webpack** — import from `"concealjs"` (this file). WASM is bundled;
 *   `crypto` / `cypher` work immediately after import.
 * - **Browser without a bundler** — resolves to `src/browser.js` via the `"browser"`
 *   field; call `await init()` once before `crypto` / `cypher`. See `concealjs/browser`.
 *
 * @example
 * ```js
 * import { mnemonic, crypto, cypher } from "concealjs";
 *
 * const seed = mnemonic.mn_random(256);
 * const phrase = mnemonic.mn_encode(seed);
 * const wallet = crypto.create_address(seed);
 * ```
 */

export * as mnemonic from "./js/mnemonic.js";
export * as crypto   from "./wasm/crypto/crypto.js";
export * as cypher   from "./wasm/cypher/cypher.js";
