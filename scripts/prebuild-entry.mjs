/**
 * esbuild entry: sync-init inlined WASM, expose API (Promise for RequireJS compatibility).
 */
import * as mnemonic from "../src/js/mnemonic.js";
import { initSync as initCryptoSync } from "../src/wasm-browser/crypto/crypto.js";
import { initSync as initCypherSync } from "../src/wasm-browser/cypher/cypher.js";
import * as crypto from "../src/wasm-browser/crypto/crypto.js";
import * as cypher from "../src/wasm-browser/cypher/cypher.js";
import cryptoWasm from "../src/wasm-browser/crypto/crypto_bg.wasm";
import cypherWasm from "../src/wasm-browser/cypher/cypher_bg.wasm";

initCryptoSync({ module: cryptoWasm });
initCypherSync({ module: cypherWasm });

globalThis.concealjs = { mnemonic, crypto, cypher };
