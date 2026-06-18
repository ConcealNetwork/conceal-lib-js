/**
 * Encode a standard CCX address from spend + view public keys.
 *
 * @param {string} spendPub - 64-char hex spend public key.
 * @param {string} viewPub - 64-char hex view public key.
 * @returns {string} Base58 CCX address.
 */
export function encode_address(spendPub: string, viewPub: string): string;
/**
 * Encode a CCX integrated address (embeds an 8-byte payment ID).
 *
 * @param {string} spendPub - 64-char hex spend public key.
 * @param {string} viewPub - 64-char hex view public key.
 * @param {string} paymentId - 16-char hex payment ID.
 * @returns {string} Base58 CCX integrated address.
 */
export function encode_integrated_address(spendPub: string, viewPub: string, paymentId: string): string;
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
export function decode_address(address: string): {
    spend: string;
    view: string;
    intPaymentId: string | null;
};
/** CCX mainnet public address prefix. */
export const ADDRESS_PREFIX: 31444;
/** CCX mainnet integrated address prefix. */
export const INTEGRATED_ADDRESS_PREFIX: 31445;
/** CCX mainnet subaddress prefix. */
export const SUBADDRESS_PREFIX: 31446;
/** Address checksum length in bytes (8 hex chars). */
export const ADDRESS_CHECKSUM_SIZE: 4;
/** Integrated payment ID length in bytes (16 hex chars). */
export const INTEGRATED_ID_SIZE: 8;
export { decode as base58_decode, encode as base58_encode } from "./base58.js";
