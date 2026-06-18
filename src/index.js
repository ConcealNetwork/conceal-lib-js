/**
 * @module concealjs
 *
 * One-stop cryptographic library for Conceal Network.
 *
 * Namespaces exported:
 *
 * - **`mnemonic`** — `mn_encode`, `mn_decode`, `mn_random` (plain JS, no WASM).
 *   ~2.8× faster than the Rust WASM build for string-heavy mnemonic operations.
 *
 * - **`crypto`** — Keccak-256, EC scalar/point operations, key derivation,
 *   and address encoding/decoding.  All functions match the names used in
 *   `conceal-web-wallet/src/model/Cn.ts`.  Compiled from Rust to WASM.
 *
 * - **`cnutils`** — hex/scalar helpers and curve utilities from `CnUtils` in
 *   `conceal-web-wallet/src/model/Cn.ts` (JS + nacl.ll + WASM hash/scalar ops).
 *
 * - **`cypher`** — ChaCha8, ChaCha12, and ChaCha20 stream ciphers (32-byte key,
 *   12-byte nonce).  Compiled from Rust to WASM.
 *
 * - **`cn`** — `random_keypair`, `underive_public_key` (JS + WASM).
 * - **`transactions`** — `ownsTx`, receive/spend scan helpers (JS + WASM).
 * - **`address`** — address encoding for view-only / integrated addresses
 *   (`encode_address`, `encode_integrated_address`) plus CryptoNote base58
 *   (JS tier, no WASM).
 * - **`random`** — `rand32`, `rand16`, `rand8` (browser entropy via `mnemonic`).
 *
 * - **`sha3_384`** — SHA3-384 (NIST padding) as lowercase hex (plain JS, `tiers/sha3.js`).
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
 * import { mnemonic, cnutils, crypto, cypher } from "concealjs";
 *
 * const seed = mnemonic.mn_random(256);
 * const phrase = mnemonic.mn_encode(seed);
 * const wallet = crypto.create_address(seed);
 * ```
 */

export * as mnemonic from "./js/mnemonic.js";
export * as cnutils  from "./js/cnutils.js";
export * as random   from "./js/random.js";
export * as cn           from "./js/cn.js";
export * as transactions from "./js/transactions.js";
export * as address      from "./js/address.js";
export * as crypto       from "./wasm/crypto/crypto.js";
export * as cypher   from "./wasm/cypher/cypher.js";
export { sha3_384 } from "./js/tiers/sha3.js";
