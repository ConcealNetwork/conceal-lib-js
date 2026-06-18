/**
 * Encode a hex string to a CryptoNote base58 string.
 *
 * @param {string} hex - Even-length hex string.
 * @returns {string} Base58 string (left-padded per block with `'1'`).
 */
export function encode(hex: string): string;
/**
 * Decode a CryptoNote base58 string to a hex string.
 *
 * @param {string} enc - Base58 string.
 * @returns {string} Even-length hex string.
 */
export function decode(enc: string): string;
