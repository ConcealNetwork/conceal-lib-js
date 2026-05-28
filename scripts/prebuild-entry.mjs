import * as mnemonic from "../src/js/mnemonic.js";
import * as cnutils from "../src/js/cnutils.js";
import * as random from "../src/js/random.js";
import * as cn from "../src/js/cn.js";
import * as transactions from "../src/js/transactions.js";
import * as crypto from "../src/wasm-browser/crypto/crypto.js";
import * as cypher from "../src/wasm-browser/cypher/cypher.js";
import { sha3_384 } from "../src/js/tiers/sha3.js";
import cryptoWasm from "../src/wasm-browser/crypto/crypto_bg.wasm";
import cypherWasm from "../src/wasm-browser/cypher/cypher_bg.wasm";

crypto.initSync({ module: cryptoWasm });
cypher.initSync({ module: cypherWasm });

const concealjs = {
  mnemonic,
  cnutils,
  random,
  cn,
  transactions,
  crypto,
  cypher,
  sha3_384,
};

globalThis.concealjs = concealjs;

export default concealjs;
export {
  mnemonic,
  cnutils,
  random,
  cn,
  transactions,
  crypto,
  cypher,
  sha3_384,
};