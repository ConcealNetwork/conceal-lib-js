/**
 * CCX address encoding for view-only and integrated addresses.
 *
 * **Hybrid tier:** this module is the zero-init JavaScript path — no WASM load,
 * no `await init()`. Algorithms mirror the canonical Rust implementation in
 * `rust/crypto/src/address.rs` (same varint prefix, Keccak checksum, base58).
 *
 * When the WASM `crypto` module is already loaded, `crypto.encode_address`,
 * `crypto.encode_integrated_address`, and `crypto.decode_address` expose the
 * same behavior via Rust. Use this namespace for view-only wallets that only
 * hold public keys; use `crypto.create_address` for seed-based key generation.
 *
 * @module address
 */

import * as base58 from "./base58.js";
import { cn_fast_hash, encode_varint, valid_hex } from "./cnutils.js";

/** CCX mainnet public address prefix. */
export const ADDRESS_PREFIX = 0x7ad4;
/** CCX mainnet integrated address prefix. */
export const INTEGRATED_ADDRESS_PREFIX = 0x7ad5;
/** CCX mainnet subaddress prefix. */
export const SUBADDRESS_PREFIX = 0x7ad6;
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
  if (typeof hex !== "string" || hex.length !== length || !valid_hex(hex)) {
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
  assertHex(spendPub, PUBLIC_KEY_HEX_LENGTH, "spendPub");
  assertHex(viewPub, PUBLIC_KEY_HEX_LENGTH, "viewPub");
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
  assertHex(spendPub, PUBLIC_KEY_HEX_LENGTH, "spendPub");
  assertHex(viewPub, PUBLIC_KEY_HEX_LENGTH, "viewPub");
  assertHex(paymentId, INTEGRATED_ID_HEX_LENGTH, "paymentId");
  const prefix = encode_varint(INTEGRATED_ADDRESS_PREFIX);
  const data =
    prefix +
    spendPub.toLowerCase() +
    viewPub.toLowerCase() +
    paymentId.toLowerCase();
  const checksum = cn_fast_hash(data).slice(0, ADDRESS_CHECKSUM_SIZE * 2);
  return base58.encode(data + checksum);
}

/**
 * Decode a CCX address (standard, integrated, or subaddress) to its spend +
 * view public keys, plus the embedded payment ID for integrated addresses.
 * Validates the network prefix and the Keccak-256 checksum.
 *
 * Canonical logic lives in Rust (`address::decode_address_full`); this JS copy
 * avoids WASM init for view-only / address-only call sites.
 *
 * @param {string} address - Base58 CCX address.
 * @returns {{ spend: string, view: string, intPaymentId: string | null }}
 */
export function decode_address(address) {
  if (typeof address !== "string" || address.length === 0) {
    throw new Error("address must be a non-empty string");
  }
  const dec = base58.decode(address);

  const addrPrefix = encode_varint(ADDRESS_PREFIX);
  const intPrefix = encode_varint(INTEGRATED_ADDRESS_PREFIX);
  const subPrefix = encode_varint(SUBADDRESS_PREFIX);
  const prefix = dec.slice(0, addrPrefix.length);
  if (prefix !== addrPrefix && prefix !== intPrefix && prefix !== subPrefix) {
    throw new Error("Invalid address prefix");
  }

  const checksumHexLen = ADDRESS_CHECKSUM_SIZE * 2;
  const PUBKEYS_HEX_LEN = 128; // spend (64) + view (64)
  // Enforce an exact decoded length so trailing bytes can't be appended to a
  // valid address: the checksum sits at a fixed offset over prefix+spend+view,
  // so without this an attacker could pad the payload and still pass validation
  // (decoding to the same keys). Reject non-canonical lengths up front.
  const expectedLen =
    addrPrefix.length +
    PUBKEYS_HEX_LEN +
    (prefix === intPrefix ? INTEGRATED_ID_HEX_LENGTH : 0) +
    checksumHexLen;
  if (dec.length !== expectedLen) {
    throw new Error("Invalid address length");
  }

  const body = dec.slice(addrPrefix.length);
  const spend = body.slice(0, 64);
  const view = body.slice(64, 128);

  let intPaymentId = null;
  let checksum;
  let expectedChecksum;
  if (prefix === intPrefix) {
    const idEnd = 128 + INTEGRATED_ID_HEX_LENGTH;
    intPaymentId = body.slice(128, idEnd);
    checksum = body.slice(idEnd, idEnd + checksumHexLen);
    expectedChecksum = cn_fast_hash(prefix + spend + view + intPaymentId).slice(
      0,
      checksumHexLen,
    );
  } else {
    checksum = body.slice(128, 128 + checksumHexLen);
    expectedChecksum = cn_fast_hash(prefix + spend + view).slice(
      0,
      checksumHexLen,
    );
  }
  if (!checksum || checksum !== expectedChecksum) {
    throw new Error("Invalid checksum");
  }

  return { spend, view, intPaymentId };
}

export { decode as base58_decode, encode as base58_encode } from "./base58.js";
