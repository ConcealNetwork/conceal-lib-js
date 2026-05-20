import * as mnemonic from "../src/js/mnemonic.js";
import * as cnutils from "../src/js/cnutils.js";
import * as crypto from "../src/wasm-browser/crypto/crypto.js";
import * as cypher from "../src/wasm-browser/cypher/cypher.js";
import cryptoWasm from "../src/wasm-browser/crypto/crypto_bg.wasm";
import cypherWasm from "../src/wasm-browser/cypher/cypher_bg.wasm";

crypto.initSync({ module: cryptoWasm });
cypher.initSync({ module: cypherWasm });

const concealjs = { mnemonic, cnutils, crypto, cypher };

globalThis.concealjs = concealjs;

export default concealjs;
export { mnemonic, cnutils, crypto, cypher };