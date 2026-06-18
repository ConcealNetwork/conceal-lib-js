/**
 * Encrypt a message with XSalsa20-Poly1305 (matches `nacl.secretbox`).
 *
 * @param {Uint8Array} msg - Plaintext.
 * @param {Uint8Array} nonce - 24-byte nonce.
 * @param {Uint8Array} key - 32-byte key.
 * @returns {Uint8Array} Ciphertext (16-byte Poly1305 tag + encrypted payload).
 */
export function secretbox(msg: Uint8Array, nonce: Uint8Array, key: Uint8Array): Uint8Array;
export namespace secretbox {
    export { open };
    export { crypto_secretbox_KEYBYTES as keyLength };
    export { crypto_secretbox_NONCEBYTES as nonceLength };
    export { crypto_secretbox_BOXZEROBYTES as overheadLength };
}
/**
 * Decrypt and authenticate (matches `nacl.secretbox.open`).
 *
 * @param {Uint8Array} box - Ciphertext from {@link secretbox}.
 * @param {Uint8Array} nonce - 24-byte nonce.
 * @param {Uint8Array} key - 32-byte key.
 * @returns {Uint8Array | null} Plaintext, or `null` if authentication fails.
 */
export function open(box: Uint8Array, nonce: Uint8Array, key: Uint8Array): Uint8Array | null;
declare const crypto_secretbox_KEYBYTES: 32;
declare const crypto_secretbox_NONCEBYTES: 24;
declare const crypto_secretbox_BOXZEROBYTES: 16;
export {};
