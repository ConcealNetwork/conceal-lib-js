/* @ts-self-types="./crypto.d.ts" */
import * as wasm from "./crypto_bg.wasm";
import { __wbg_set_wasm } from "./crypto_bg.js";

__wbg_set_wasm(wasm);
wasm.__wbindgen_start();
export {
    cn_fast_hash, create_address, decode_address, derive_public_key, derive_secret_key, ge_add, ge_frombytes_vartime, ge_mul8, ge_p3_tobytes, ge_scalarmult, ge_scalarmult_base, ge_tobytes, generate_key_derivation, generate_keys, hash_to_scalar, sc_0, sc_add, sc_check, sc_mulsub, sc_reduce32, sc_sub
} from "./crypto_bg.js";
