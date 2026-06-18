/**
 * CCX address encoding for view-only and integrated addresses (JS tier, no WASM).
 *
 * Mirrors `pubkeys_to_string` in `conceal-web-wallet`: a varint network prefix,
 * the spend + view public keys, an optional integrated payment ID, and a
 * Keccak-256 checksum, all base58-encoded. Lets callers that already hold public
 * keys (view-only wallets) or a payment ID build an address without a seed and
 * without the WASM `crypto` module.
 *
 * @module address
 */

'use strict';

import * as base58 from './base58.js';
import { cn_fast_hash, encode_varint, valid_hex } from './cnutils.js';

/** CCX mainnet public address prefix. */
export const ADDRESS_PREFIX = 0x7ad4;
/** CCX mainnet integrated address prefix. */
export const INTEGRATED_ADDRESS_PREFIX = 0x7ad5;
/** Address checksum length in bytes (8 hex chars). */
export const ADDRESS_CHECKSUM_SIZE = 4;
/** Integrated payment ID length in bytes (16 hex chars). */
export const INTEGRATED_ID_SIZE = 8;

const PUBLIC_KEY_HEX_LENGTH = 64;
const INTEGRATED_ID_HEX_LENGTH = INTEGRATED_ID_SIZE * 2;

/**
 * @param {string} hex
 * @param {number} length
 * @param {string} label
 * @returns {void}
 */
function assertHex(hex, length, label) {
  if (typeof hex !== 'string' || hex.length !== length || !valid_hex(hex)) {
    throw new Error(`${label} must be a ${length}-char hex string`);
  }
}

/**
 * Encode a standard CCX address from spend + view public keys.
 *
 * @param {string} spendPub - 64-char hex spend public key.
 * @param {string} viewPub - 64-char hex view public key.
 * @returns {string} Base58 CCX address.
 */
export function encode_address(spendPub, viewPub) {
  assertHex(spendPub, PUBLIC_KEY_HEX_LENGTH, 'spendPub');
  assertHex(viewPub, PUBLIC_KEY_HEX_LENGTH, 'viewPub');
  const prefix = encode_varint(ADDRESS_PREFIX);
  const data = prefix + spendPub.toLowerCase() + viewPub.toLowerCase();
  const checksum = cn_fast_hash(data).slice(0, ADDRESS_CHECKSUM_SIZE * 2);
  return base58.encode(data + checksum);
}

/**
 * Encode a CCX integrated address (embeds an 8-byte payment ID).
 *
 * @param {string} spendPub - 64-char hex spend public key.
 * @param {string} viewPub - 64-char hex view public key.
 * @param {string} paymentId - 16-char hex payment ID.
 * @returns {string} Base58 CCX integrated address.
 */
export function encode_integrated_address(spendPub, viewPub, paymentId) {
  assertHex(spendPub, PUBLIC_KEY_HEX_LENGTH, 'spendPub');
  assertHex(viewPub, PUBLIC_KEY_HEX_LENGTH, 'viewPub');
  assertHex(paymentId, INTEGRATED_ID_HEX_LENGTH, 'paymentId');
  const prefix = encode_varint(INTEGRATED_ADDRESS_PREFIX);
  const data = prefix + spendPub.toLowerCase() + viewPub.toLowerCase() + paymentId.toLowerCase();
  const checksum = cn_fast_hash(data).slice(0, ADDRESS_CHECKSUM_SIZE * 2);
  return base58.encode(data + checksum);
}

export { decode as base58_decode, encode as base58_encode } from './base58.js';
