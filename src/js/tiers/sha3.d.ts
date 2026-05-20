/**
 * js-sha3 v0.5.1 — Keccak / SHA3 / SHAKE helpers (MIT, emn178).
 */

/** Keccak-256 (CryptoNote `cn_fast_hash` variant). Returns lowercase hex. */
export function keccak_256(message: Uint8Array | string | ArrayBuffer): string;

export function keccak_224(message: Uint8Array | string | ArrayBuffer): string;
export function keccak_384(message: Uint8Array | string | ArrayBuffer): string;
export function keccak_512(message: Uint8Array | string | ArrayBuffer): string;

declare const sha3: {
  keccak_256: typeof keccak_256;
  keccak_224: typeof keccak_224;
  keccak_384: typeof keccak_384;
  keccak_512: typeof keccak_512;
  [key: string]: (message: Uint8Array | string | ArrayBuffer, outputBits?: number) => string;
};

export default sha3;
