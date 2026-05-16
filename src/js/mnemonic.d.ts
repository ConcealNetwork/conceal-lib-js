/**
 * Supported mnemonic wordset identifiers.
 * - `'english'`  — 1626-word list, prefix length 3 (default)
 * - `'electrum'` — legacy Electrum list, no checksum word
 * - `'japanese'` — Japanese kanji list, prefix length 3
 */
export type WordsetName = 'english' | 'electrum' | 'japanese';

/**
 * Encodes a 64-char hex private spend key into a mnemonic phrase.
 *
 * Each 8 hex characters (4 bytes) produce 3 words; a final checksum word is
 * appended for wordsets that have `prefix_len > 0` (all except Electrum).
 * The result is a space-separated string of 25 words for English/Japanese
 * or 24 words for Electrum.
 *
 * @param str - 64-character lowercase hex string (32-byte private key).
 * @param wordset_name - Wordset to use. Defaults to `'english'`.
 * @returns Space-separated mnemonic phrase.
 * @throws If the wordset is unknown or the input length is invalid.
 */
export function mn_encode(str: string, wordset_name?: WordsetName): string;

/**
 * Decodes a mnemonic phrase back into a 64-char hex private spend key.
 *
 * Validates the checksum word (for wordsets with `prefix_len > 0`) and
 * throws a descriptive error if the phrase is malformed or unverifiable.
 * Only the first `prefix_len` characters of each word are significant;
 * full words are accepted and compared by prefix.
 *
 * @param str - Space-separated mnemonic phrase (25 words for English).
 * @param wordset_name - Wordset to use. Defaults to `'english'`.
 * @returns 64-character lowercase hex string (32-byte private key).
 * @throws If too few words are given, a word is unrecognised, or the
 *   checksum word does not match.
 */
export function mn_decode(str: string, wordset_name?: WordsetName): string;

/**
 * Generates a cryptographically random seed as a lowercase hex string.
 *
 * Uses `window.crypto.getRandomValues` — **browser-only**.  Retries up to
 * 5 times before throwing if the CSPRNG returns all-zero output.
 *
 * The returned value is raw entropy and is **not** automatically reduced
 * modulo the Ed25519 group order.  Pass it through `crypto.sc_reduce32`
 * before using it as a private key.
 *
 * @param bits - Number of random bits.  Must be a positive multiple of 32;
 *   typically `256` for a 32-byte seed.
 * @returns Lowercase hex string of length `bits / 4`.
 * @throws If `bits` is not a multiple of 32, the browser does not support
 *   the Web Crypto API, or random generation fails after 5 retries.
 */
export function mn_random(bits: number): string;
