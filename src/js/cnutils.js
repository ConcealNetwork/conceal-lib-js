/**
 * CryptoNote utility helpers from `CnUtils` in conceal-web-wallet `Cn.ts`.
 *
 * Pure hex/integer helpers and `cn_fast_hash` (Keccak-256 via `tiers/sha3.js`) run in
 * JavaScript; curve ops use `nacl.ll` (TweetNaCl CN extensions); scalar helpers and
 * `hash_to_ec32` / `hash_to_ec160` delegate to the Rust/WASM `crypto` module.
 *
 * @module cnutils
 */

import wasmCrypto from "#cnutils-wasm";
import { JSBigInt } from "./tiers/biginteger.js";
import nacl from "./tiers/nacl.js";
import { keccak_256 } from "./tiers/sha3.js";

const wasm_hash_to_scalar = wasmCrypto.hash_to_scalar;
const wasm_sc_add = wasmCrypto.sc_add;
const wasm_sc_sub = wasmCrypto.sc_sub;

/** @type {Readonly<{ EC_POINT: number }>} */
export const STRUCT_SIZES = Object.freeze({
  GE_P3: 160,
  GE_P2: 120,
  GE_P1P1: 160,
  GE_CACHED: 160,
  EC_SCALAR: 32,
  EC_POINT: 32,
  KEY_IMAGE: 32,
  GE_DSMP: 160 * 8,
  SIGNATURE: 64,
});

/**
 * Decode a validated hex string to bytes.
 *
 * @param {string} hex - Validated hex string (`""` decodes to an empty array).
 * @returns {Uint8Array}
 * @throws {Error} If `hex` is not a string, contains non-hex characters, or has odd length.
 */
export function hextobin(hex) {
  if (typeof hex !== "string" || !/^[0-9a-fA-F]*$/.test(hex)) {
    throw new Error("Invalid hex string");
  }
  if (hex.length % 2 !== 0) throw new Error("Hex string has invalid length!");
  const res = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length / 2; ++i) {
    res[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return res;
}

/**
 * @param {Uint8Array | string} bin
 * @returns {string}
 */
export function bintohex(bin) {
  const out = [];
  if (typeof bin === "string") {
    for (let i = 0; i < bin.length; ++i) {
      out.push(`0${bin.charCodeAt(i).toString(16)}`.slice(-2));
    }
  } else {
    for (let i = 0; i < bin.length; ++i) {
      out.push(`0${bin[i].toString(16)}`.slice(-2));
    }
  }
  return out.join("");
}

/**
 * Reverse the byte order of a hex string (little-endian ↔ big-endian).
 *
 * @param {string} hex - Even-length hex string.
 * @returns {string} Byte-swapped hex string.
 * @throws {TypeError} If `hex` is not a string.
 * @throws {Error} If `hex` contains non-hex characters or has odd length.
 */
export function swapEndian(hex) {
  if (typeof hex !== "string") {
    throw new TypeError("swapEndian expects a hex string");
  }
  if (!/^[0-9a-fA-F]*$/.test(hex)) {
    throw new Error("Invalid hex string");
  }
  if (hex.length % 2 !== 0) {
    throw new Error("Hex string has invalid length!");
  }
  let data = "";
  for (let i = 1; i <= hex.length / 2; i++) {
    data += hex.substr(0 - 2 * i, 2);
  }
  return data;
}

/**
 * @param {string} string
 * @returns {string}
 */
export function swapEndianC(string) {
  let data = "";
  for (let i = 1; i <= string.length; i++) {
    data += string.substr(0 - i, 1);
  }
  return data;
}

/**
 * Format a non-negative integer as 64-char lowercase hex (big-endian).
 *
 * @param {number | string} integer - Non-negative integer (pass large values as strings).
 * @returns {string} 64-char lowercase hex.
 * @throws {TypeError} If `integer` is not a number or decimal string.
 * @throws {Error} If `integer` is negative or fractional, a number too large for exact formatting, or ≥ 2^256.
 */
export function d2h(integer) {
  if (typeof integer !== "number" && typeof integer !== "string") {
    throw new TypeError("d2h expects a number or decimal string");
  }
  const integerStr = typeof integer === "number" ? integer.toString() : integer;
  if (!/^\d+$/.test(integerStr)) {
    throw new Error("d2h expects a non-negative integer");
  }
  if (typeof integer !== "string" && integerStr.length > 15) {
    throw new Error("integer should be entered as a string for precision");
  }
  let padding = "";
  for (let i = 0; i < 63; i++) {
    padding += "0";
  }
  const hex = new JSBigInt(integerStr).toString(16).toLowerCase();
  if (hex.length > 64) {
    throw new Error("value overflows 2^256!");
  }
  return (padding + hex).slice(-64);
}

/**
 * Format a non-negative integer as 64-char lowercase hex (little-endian).
 *
 * @param {number | string} integer - Non-negative integer (pass large values as strings).
 * @returns {string} 64-char lowercase hex.
 * @throws {TypeError} If `integer` is not a number or decimal string.
 * @throws {Error} If `integer` is negative or fractional, a number too large for exact formatting, or ≥ 2^256.
 */
export function d2s(integer) {
  if (typeof integer !== "number" && typeof integer !== "string") {
    throw new TypeError("d2s expects a number or decimal string");
  }
  if (typeof integer === "string") {
    return swapEndian(d2h(integer));
  }
  return swapEndian(d2h(integer.toString()));
}

/**
 * Decode 8 little-endian bytes (16 hex chars) to a JS number.
 *
 * @param {string} hex - Exactly 16 hex characters (8 bytes, little-endian order).
 * @returns {number} Unsigned integer value of those 8 bytes.
 * @throws {Error} If `hex` is not a 16-character hex string, or the value exceeds `Number.MAX_SAFE_INTEGER`.
 */
export function h2d(hex) {
  if (typeof hex !== "string" || hex.length !== 16 || !valid_hex(hex)) {
    throw new Error("h2d expects a 16-character hex string");
  }
  // hex is little-endian; compare its byte-reversed value against MAX_SAFE_INTEGER
  if (
    BigInt(`0x${hex.match(/.{2}/g).reverse().join("")}`) >
    BigInt(Number.MAX_SAFE_INTEGER)
  ) {
    throw new Error("h2d value exceeds Number.MAX_SAFE_INTEGER");
  }
  let vali = 0;
  for (let j = 7; j >= 0; j--) {
    vali = vali * 256 + Number.parseInt(hex.slice(j * 2, j * 2 + 2), 16);
  }
  return vali;
}

/**
 * Format a non-negative integer as a 64-bit little-endian bit-string.
 *
 * @param {number | string} integer - Non-negative integer (pass large values as strings).
 * @returns {string} 64-character bit-string.
 * @throws {TypeError} If `integer` is not a number or decimal string.
 * @throws {Error} If `integer` is negative or fractional, or a number too large for exact formatting, or overflows uint64.
 */
export function d2b(integer) {
  if (typeof integer !== "number" && typeof integer !== "string") {
    throw new TypeError("d2b expects a number or decimal string");
  }
  const integerStr = typeof integer === "number" ? integer.toString() : integer;
  if (!/^\d+$/.test(integerStr)) {
    throw new Error("d2b expects a non-negative integer");
  }
  if (typeof integer !== "string" && integerStr.length > 15) {
    throw new Error("integer should be entered as a string for precision");
  }
  let padding = "";
  for (let i = 0; i < 63; i++) {
    padding += "0";
  }
  const a = new JSBigInt(integerStr);
  if (a.toString(2).length > 64) {
    throw new Error("amount overflows uint64!");
  }
  return swapEndianC((padding + a.toString(2)).slice(-64));
}

/**
 * @param {string} pub
 * @param {string} sec
 * @returns {string}
 */
export function ge_scalarmult(pub, sec) {
  if (pub.length !== 64 || sec.length !== 64) {
    throw new Error("Invalid input length");
  }
  return bintohex(nacl.ll.ge_scalarmult(hextobin(pub), hextobin(sec)));
}

/**
 * @param {string} p1
 * @param {string} p2
 * @returns {string}
 */
export function ge_add(p1, p2) {
  if (p1.length !== 64 || p2.length !== 64) {
    throw new Error("Invalid input length!");
  }
  return bintohex(nacl.ll.ge_add(hextobin(p1), hextobin(p2)));
}

/**
 * Negate an Ed25519 compressed point by flipping the sign bit in the high
 * nibble of the last byte (`point[62]` ± 8).
 *
 * @param {string} point - 64-character compressed point hex.
 * @returns {string} 64-character hex encoding of `-point`.
 * @throws {Error} If `point` is not a 64-character hex string.
 */
export function ge_neg(point) {
  if (typeof point !== "string" || point.length !== 64 || !valid_hex(point)) {
    throw new Error("expected 64 char hex string");
  }
  return (
    point.slice(0, 62) +
    ((Number.parseInt(point.slice(62, 63), 16) + 8) % 16).toString(16) +
    point.slice(63, 64)
  );
}

/**
 * Subtract two Ed25519 compressed points (`point1 - point2`).
 *
 * @param {string} point1 - 64-character compressed point hex.
 * @param {string} point2 - 64-character compressed point hex.
 * @returns {string} 64-character hex encoding of `point1 - point2`.
 * @throws {Error} If either point fails `ge_add` / `ge_neg` validation.
 */
export function ge_sub(point1, point2) {
  return ge_add(point1, ge_neg(point2));
}

/**
 * @param {string} sec
 * @returns {string}
 */
export function sec_key_to_pub(sec) {
  if (sec.length !== 64) {
    throw new Error("Invalid sec length");
  }
  return bintohex(nacl.ll.ge_scalarmult_base(hextobin(sec)));
}

/**
 * @param {string} hex
 * @returns {boolean}
 */
export function valid_hex(hex) {
  const exp = new RegExp(`[0-9a-fA-F]{${hex.length}}`);
  return exp.test(hex);
}

/**
 * @param {string} sec
 * @returns {string}
 */
export function ge_scalarmult_base(sec) {
  return sec_key_to_pub(sec);
}

/**
 * @param {string} derivation
 * @param {number} output_index
 * @returns {string}
 */
export function derivation_to_scalar(derivation, output_index) {
  let buf = "";
  if (derivation.length !== STRUCT_SIZES.EC_POINT * 2) {
    throw new Error("Invalid derivation length!");
  }
  buf += derivation;
  const enc = encode_varint(output_index);
  if (enc.length > 10 * 2) {
    throw new Error("output_index didn't fit in 64-bit varint");
  }
  buf += enc;
  return wasm_hash_to_scalar(buf);
}

/**
 * @param {number | string} i
 * @returns {import("./tiers/biginteger.js").JSBigInt}
 * @throws {Error} If `i` is missing, non-numeric, fractional, or negative.
 */
function requireNonNegativeVarint(i) {
  if (i === undefined || i === null) {
    throw new Error("varint input is required");
  }
  if (typeof i === "number" && !Number.isInteger(i)) {
    throw new Error("varint input must be an integer");
  }
  const value = new JSBigInt(i);
  if (value.isNegative()) {
    throw new Error("varint cannot be negative");
  }
  if (typeof i === "string" && !/^\d+$/.test(i)) {
    throw new Error("varint input must be a non-negative integer");
  }
  return value;
}

/**
 * Encode an unsigned CryptoNote varint as lowercase hex.
 *
 * @param {number | string} i - Non-negative integer (or decimal string).
 * @returns {string} Even-length lowercase hex.
 * @throws {Error} If `i` is missing, non-numeric, fractional, or negative.
 */
export function encode_varint(i) {
  let j = requireNonNegativeVarint(i);
  let out = "";
  while (j.compare(0x80) >= 0) {
    out += `0${((j.lowVal() & 0x7f) | 0x80).toString(16)}`.slice(-2);
    j = j.divide(new JSBigInt(2).pow(7));
  }
  out += `0${j.toJSValue().toString(16)}`.slice(-2);
  return out;
}

/**
 * Encode an unsigned CryptoNote term varint as lowercase hex.
 *
 * @param {number | string} i - Non-negative integer (or decimal string).
 * @returns {string} Even-length lowercase hex.
 * @throws {Error} If `i` is missing, non-numeric, fractional, or negative.
 */
export function encode_varint_term(i) {
  let value = requireNonNegativeVarint(i);
  let out = "";
  do {
    const byteValue = value.lowVal() & 0xff;
    const byte = value.compare(0x7f) > 0 ? byteValue | 0x80 : byteValue;
    out += byte.toString(16).padStart(2, "0");
    value = value.divide(0x80);
  } while (value.compare(0) > 0);
  return out;
}

/**
 * Keccak-256 of hex-decoded input (`CnUtils.cn_fast_hash` / wallet `keccak_256`).
 *
 * @param {string} input - Even-length hex string.
 * @returns {string} 64-char lowercase hex digest.
 */
export function cn_fast_hash(input) {
  if (input.length % 2 !== 0 || !valid_hex(input)) {
    throw new Error("Input invalid");
  }
  return keccak_256(hextobin(input));
}

/**
 * @param {string} hex1
 * @param {string} hex2
 * @returns {string}
 */
export function hex_xor(hex1, hex2) {
  if (
    !hex1 ||
    !hex2 ||
    hex1.length !== hex2.length ||
    hex1.length % 2 !== 0 ||
    hex2.length % 2 !== 0
  ) {
    throw new Error("Hex string(s) is/are invalid!");
  }
  const bin1 = hextobin(hex1);
  const bin2 = hextobin(hex2);
  const xor = new Uint8Array(bin1.length);
  for (let i = 0; i < xor.length; i++) {
    xor[i] = bin1[i] ^ bin2[i];
  }
  return bintohex(xor);
}

/**
 * @param {string} str
 * @param {string} char
 * @returns {string}
 */
export function trimRight(str, char) {
  while (str[str.length - 1] === char) str = str.slice(0, -1);
  return str;
}

/**
 * @param {string} str
 * @param {number} len
 * @param {string} char
 * @returns {string}
 */
export function padLeft(str, len, char) {
  while (str.length < len) {
    str = char + str;
  }
  return str;
}

/**
 * @param {string} c
 * @param {string} P
 * @param {string} r
 * @returns {string}
 */
export function ge_double_scalarmult_base_vartime(c, P, r) {
  if (c.length !== 64 || P.length !== 64 || r.length !== 64) {
    throw new Error("Invalid input length!");
  }
  return bintohex(
    nacl.ll.ge_double_scalarmult_base_vartime(
      hextobin(c),
      hextobin(P),
      hextobin(r),
    ),
  );
}

/**
 * `r·hash_to_ec32(P) + c·I` (wallet postcomp path; needs 32-byte compressed `Pb`).
 *
 * @param {string} r - 64-char hex scalar.
 * @param {string} P - 64-char hex public key (compressed point input to `hash_to_ec32`).
 * @param {string} c - 64-char hex scalar.
 * @param {string} I - 64-char hex point.
 * @returns {string} 64-char hex point.
 */
export function ge_double_scalarmult_postcomp_vartime(r, P, c, I) {
  if (
    c.length !== 64 ||
    P.length !== 64 ||
    r.length !== 64 ||
    I.length !== 64
  ) {
    throw new Error("Invalid input length!");
  }
  if (typeof wasmCrypto.hash_to_ec32 !== "function") {
    throw new Error(
      "hash_to_ec32 is not in crypto WASM; run npm run build:crypto",
    );
  }
  const Pb = wasmCrypto.hash_to_ec32(P);
  return bintohex(
    nacl.ll.ge_double_scalarmult_postcomp_vartime(
      hextobin(r),
      hextobin(Pb),
      hextobin(c),
      hextobin(I),
    ),
  );
}

/**
 * Decompose a non-negative integer amount into power-of-ten digit components.
 *
 * @param {number | string} amount - Non-negative integer (or decimal string).
 * @returns {import('./tiers/biginteger.js').JSBigInt[]} Digit components, most significant first.
 * @throws {TypeError} If `amount` is not a number or decimal string.
 * @throws {Error} If `amount` is negative or fractional.
 */
export function decompose_amount_into_digits(amount) {
  if (typeof amount !== "number" && typeof amount !== "string") {
    throw new TypeError("amount must be a number or decimal string");
  }
  amount = typeof amount === "number" ? amount.toString() : amount;
  if (!/^\d+$/.test(amount)) {
    throw new Error("amount must be a non-negative integer");
  }
  const ret = [];
  while (amount.length > 0) {
    if (amount[0] !== "0") {
      let digit = amount[0];
      while (digit.length < amount.length) {
        digit += "0";
      }
      ret.push(new JSBigInt(digit));
    }
    amount = amount.slice(1);
  }
  return ret;
}

/**
 * @typedef {Object} RctEcdh
 * @property {string} mask
 * @property {string} amount
 */

/**
 * @param {RctEcdh} ecdh
 * @param {string} key
 * @returns {RctEcdh}
 */
export function decode_rct_ecdh(ecdh, key) {
  const first = wasm_hash_to_scalar(key);
  const second = wasm_hash_to_scalar(first);
  return {
    mask: wasm_sc_sub(ecdh.mask, first),
    amount: wasm_sc_sub(ecdh.amount, second),
  };
}

/**
 * @param {RctEcdh} ecdh
 * @param {string} key
 * @returns {RctEcdh}
 */
export function encode_rct_ecdh(ecdh, key) {
  const first = wasm_hash_to_scalar(key);
  const second = wasm_hash_to_scalar(first);
  return {
    mask: wasm_sc_add(ecdh.mask, first),
    amount: wasm_sc_add(ecdh.amount, second),
  };
}
