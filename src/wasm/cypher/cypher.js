/* @ts-self-types="./cypher.d.ts" */
import * as wasm from "./cypher_bg.wasm";
import { __wbg_set_wasm } from "./cypher_bg.js";

__wbg_set_wasm(wasm);
wasm.__wbindgen_start();
export {
    chacha12, chacha20, chacha8
} from "./cypher_bg.js";
