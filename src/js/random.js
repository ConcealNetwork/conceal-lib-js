/**
 * Random hex entropy for Conceal Network.
 *
 * `rand*` helpers use the browser Web Crypto API via `mnemonic.mn_random`.
 * `random_scalar` additionally uses WASM `sc_reduce32` (canonical scalar mod *l*).
 *
 * @module random
 */

'use strict';

import { mn_random } from './mnemonic.js';
import wasmCrypto from '#cnutils-wasm';
const { sc_reduce32 } = wasmCrypto;

/**
 * 256-bit (32-byte) seed as a 64-character lowercase hex string.
 * @returns {string}
 */
export function rand32() {
  return mn_random(256);
}

/**
 * 128-bit (16-byte) value as a 32-character lowercase hex string.
 * @returns {string}
 */
export function rand16() {
  return mn_random(128);
}

/**
 * 64-bit (8-byte) value as a 16-character lowercase hex string.
 * @returns {string}
 */
export function rand8() {
  return mn_random(64);
}

/**
 * Random canonical Ed25519 scalar as 64-character lowercase hex.
 *
 * Equivalent to `crypto.sc_reduce32(rand32())` — same reduction used for
 * `generate_keys` secret keys.
 *
 * @returns {string}
 */
export function random_scalar() {
  return sc_reduce32(rand32());
}