/**
 * Browser entry for concealjs.
 *
 * Uses wasm-pack `web` targets (`src/wasm-browser/*`) so `.wasm` files load via
 * `import.meta.url` (no bundler required). Call `init()` once before using
 * `crypto` or `cypher`.
 *
 * @example
 * ```js
 * import { init, mnemonic, crypto } from "concealjs";
 *
 * await init();
 * const seed = mnemonic.mn_random(256);
 * const wallet = crypto.create_address(seed);
 * ```
 *
 * @example
 * ```js
 * import { init, mnemonic, crypto } from "concealjs/browser";
 * await init();
 * ```
 */

export * as address from "./js/address.js";
export * as cn from "./js/cn.js";
export * as cnutils from "./js/cnutils.js";
export * as mnemonic from "./js/mnemonic.js";
export * as random from "./js/random.js";
export * as transactions from "./js/transactions.js";

import initCrypto from "./wasm-browser/crypto/crypto.js";
import initCypher from "./wasm-browser/cypher/cypher.js";

export { sha3_384 } from "./js/tiers/sha3.js";
export * as crypto from "./wasm-browser/crypto/crypto.js";
export * as cypher from "./wasm-browser/cypher/cypher.js";

let initPromise = null;

/**
 * Load crypto and cypher WASM modules. Safe to call multiple times.
 * @returns {Promise<void>}
 */
export function init() {
  if (!initPromise) {
    initPromise = Promise.all([initCrypto(), initCypher()]);
  }
  return initPromise;
}
