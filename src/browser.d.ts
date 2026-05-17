/**
 * Browser entry — call `init()` before using `crypto` or `cypher`.
 */
export function init(): Promise<void>;

export * as mnemonic from "./js/mnemonic";
export * as crypto from "./wasm-browser/crypto/crypto";
export * as cypher from "./wasm-browser/cypher/cypher";
