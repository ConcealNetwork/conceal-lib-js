/**
 * CryptoNote block-based base58 (encode + decode), ported from the legacy
 * `cnBase58` implementation in `conceal-web-wallet`.
 *
 * Faithful translation of the canonical CryptoNote algorithm with one change:
 * the legacy `JSBigInt` arithmetic is replaced with native `BigInt` (no external
 * bigint dependency). Pure JS, no globals — runs identically in Node and the
 * browser without `await init()`.
 *
 * @module base58
 */

const alphabet_str =
  "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const alphabet = [];
for (let i = 0; i < alphabet_str.length; i++) {
  alphabet.push(alphabet_str.charCodeAt(i));
}
const encoded_block_sizes = [0, 2, 3, 5, 6, 7, 9, 10, 11];

const alphabet_size = BigInt(alphabet.length);
const full_block_size = 8;
const full_encoded_block_size = 11;

// Largest value representable in 8 bytes (2^64 - 1). A decoded full block must
// not exceed this — using 2^64 here would let a crafted block equal to exactly
// 2^64 pass the overflow check and silently truncate to zero, breaking the
// CryptoNote base58 bijection (address malleability). See decode_block below.
const UINT64_MAX = 2n ** 64n - 1n;

/**
 * @param {string} hex
 * @returns {Uint8Array}
 */
function hextobin(hex) {
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
 * @param {Uint8Array} bin
 * @returns {string}
 */
function bintohex(bin) {
  const out = [];
  for (let i = 0; i < bin.length; ++i) {
    out.push(`0${bin[i].toString(16)}`.slice(-2));
  }
  return out.join("");
}

/**
 * @param {string} str
 * @returns {Uint8Array}
 */
function strtobin(str) {
  const res = new Uint8Array(str.length);
  for (let i = 0; i < str.length; i++) {
    res[i] = str.charCodeAt(i);
  }
  return res;
}

/**
 * @param {Uint8Array} bin
 * @returns {string}
 */
function bintostr(bin) {
  const out = [];
  for (let i = 0; i < bin.length; i++) {
    out.push(String.fromCharCode(bin[i]));
  }
  return out.join("");
}

/**
 * Big-endian byte array (1..8 bytes) → unsigned 64-bit `BigInt`.
 *
 * @param {Uint8Array} data
 * @returns {bigint}
 */
function uint8_be_to_64(data) {
  if (data.length < 1 || data.length > 8) {
    throw new Error("Invalid input length");
  }
  let res = 0n;
  for (let i = 0; i < data.length; i++) {
    res = res * 256n + BigInt(data[i]);
  }
  return res;
}

/**
 * Unsigned 64-bit `BigInt` → big-endian byte array of `size` (1..8) bytes.
 *
 * @param {bigint} num
 * @param {number} size
 * @returns {Uint8Array}
 */
function uint64_to_8be(num, size) {
  const res = new Uint8Array(size);
  if (size < 1 || size > 8) {
    throw new Error("Invalid input length");
  }
  for (let i = size - 1; i >= 0; i--) {
    res[i] = Number(num % 256n);
    num = num / 256n;
  }
  return res;
}

/**
 * Encode a single 1..8 byte block into `buf` at `index`.
 *
 * @param {Uint8Array} data
 * @param {Uint8Array} buf
 * @param {number} index
 * @returns {Uint8Array}
 */
function encode_block(data, buf, index) {
  if (data.length < 1 || data.length > full_block_size) {
    throw new Error(`Invalid block length: ${data.length}`);
  }
  let num = uint8_be_to_64(data);
  let i = encoded_block_sizes[data.length] - 1;
  // while num > 0
  while (num > 0n) {
    const remainder = num % alphabet_size;
    num = num / alphabet_size;
    buf[index + i] = alphabet[Number(remainder)];
    i--;
  }
  return buf;
}

/**
 * Encode a hex string to a CryptoNote base58 string.
 *
 * @param {string} hex - Even-length hex string.
 * @returns {string} Base58 string (left-padded per block with `'1'`).
 */
export function encode(hex) {
  const data = hextobin(hex);
  if (data.length === 0) {
    return "";
  }
  const full_block_count = Math.floor(data.length / full_block_size);
  const last_block_size = data.length % full_block_size;
  const res_size =
    full_block_count * full_encoded_block_size +
    encoded_block_sizes[last_block_size];

  const res = new Uint8Array(res_size);
  for (let i = 0; i < res_size; ++i) {
    res[i] = alphabet[0];
  }
  for (let i = 0; i < full_block_count; i++) {
    encode_block(
      data.subarray(i * full_block_size, i * full_block_size + full_block_size),
      res,
      i * full_encoded_block_size,
    );
  }
  if (last_block_size > 0) {
    encode_block(
      data.subarray(
        full_block_count * full_block_size,
        full_block_count * full_block_size + last_block_size,
      ),
      res,
      full_block_count * full_encoded_block_size,
    );
  }
  return bintostr(res);
}

/**
 * Decode a single base58-encoded block into `buf` at `index`.
 *
 * @param {Uint8Array} data
 * @param {Uint8Array} buf
 * @param {number} index
 * @returns {Uint8Array}
 */
function decode_block(data, buf, index) {
  if (data.length < 1 || data.length > full_encoded_block_size) {
    throw new Error(`Invalid block length: ${data.length}`);
  }

  const res_size = encoded_block_sizes.indexOf(data.length);
  if (res_size <= 0) {
    throw new Error("Invalid block size");
  }
  let res_num = 0n;
  let order = 1n;
  for (let i = data.length - 1; i >= 0; i--) {
    const digit = alphabet.indexOf(data[i]);
    if (digit < 0) {
      throw new Error("Invalid symbol");
    }
    const product = order * BigInt(digit) + res_num;
    // if product > UINT64_MAX
    if (product > UINT64_MAX) {
      throw new Error("Overflow");
    }
    res_num = product;
    order = order * alphabet_size;
  }
  if (res_size < full_block_size && 2n ** BigInt(8 * res_size) <= res_num) {
    throw new Error("Overflow 2");
  }
  buf.set(uint64_to_8be(res_num, res_size), index);
  return buf;
}

/**
 * Decode a CryptoNote base58 string to a hex string.
 *
 * @param {string} enc - Base58 string.
 * @returns {string} Even-length hex string.
 */
export function decode(enc) {
  if (typeof enc !== "string") {
    throw new Error("Base58 input must be a string");
  }
  const data_bin = strtobin(enc);
  if (data_bin.length === 0) {
    return "";
  }
  const full_block_count = Math.floor(
    data_bin.length / full_encoded_block_size,
  );
  const last_block_size = data_bin.length % full_encoded_block_size;
  const last_block_decoded_size = encoded_block_sizes.indexOf(last_block_size);
  if (last_block_decoded_size < 0) {
    throw new Error("Invalid encoded length");
  }
  const data_size =
    full_block_count * full_block_size + last_block_decoded_size;
  const data = new Uint8Array(data_size);
  for (let i = 0; i < full_block_count; i++) {
    decode_block(
      data_bin.subarray(
        i * full_encoded_block_size,
        i * full_encoded_block_size + full_encoded_block_size,
      ),
      data,
      i * full_block_size,
    );
  }
  if (last_block_size > 0) {
    decode_block(
      data_bin.subarray(
        full_block_count * full_encoded_block_size,
        full_block_count * full_encoded_block_size + last_block_size,
      ),
      data,
      full_block_count * full_block_size,
    );
  }
  return bintohex(data);
}
