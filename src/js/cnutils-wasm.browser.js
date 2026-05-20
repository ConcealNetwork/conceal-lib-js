/**
 * Browser / prebuild WASM backend for `cnutils` (`wasm-browser` web target).
 * Call `init()` on `crypto` before importing `cnutils`.
 *
 * @module cnutils-wasm
 */

import * as wasmCrypto from '../wasm-browser/crypto/crypto.js';

export default wasmCrypto;
