/**
 * High-level Conceal key helpers (`Cn`-style wallet operations).
 *
 * @module cn
 */

import wasmCrypto from "#cnutils-wasm";
import { derivation_to_scalar, ge_sub } from "./cnutils.js";
import { rand32 } from "./random.js";

const { generate_keys, ge_scalarmult_base } = wasmCrypto;

/**
 * @typedef {Object} KeyPair
 * @property {string} sec - 64-character hex secret key.
 * @property {string} pub - 64-character hex public key.
 */

/**
 * Generate a random spend/view-style key pair from secure entropy.
 * @returns {KeyPair}
 */
export function random_keypair() {
  const seed = rand32();
  return generate_keys(seed);
}

/**
 * Undo `crypto.derive_public_key`: recover the base public key from a derived one.
 *
 * @param {string} derivation - 64-character hex derivation (32-byte EC point).
 * @param {number} out_index - Output index passed to derivation_to_scalar.
 * @param {string} pub - 64-character hex derived public key.
 * @returns {string} Base public key hex (64 characters).
 * @throws {Error} If `derivation` or `pub` is not 64 hex characters.
 */
export function underive_public_key(derivation, out_index, pub) {
  if (derivation.length !== 64 || pub.length !== 64) {
    throw new Error("Invalid input length");
  }
  const s = derivation_to_scalar(derivation, out_index);
  return ge_sub(pub, ge_scalarmult_base(s));
}
