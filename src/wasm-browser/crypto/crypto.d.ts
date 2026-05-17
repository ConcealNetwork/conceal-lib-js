/* tslint:disable */
/* eslint-disable */

/**
 * cn_fast_hash: Keccak-256 of hex-decoded input.
 * Matches `CnUtils.cn_fast_hash(hex)` in Cn.ts.
 */
export function cn_fast_hash(data_hex: string): string;

/**
 * create_address: full wallet key generation from a 32-byte reduced seed.
 * Returns `{spend:{sec,pub}, view:{sec,pub}, public_addr}`.
 * Matches `Cn.create_address(seed)` for 64-char hex input.
 */
export function create_address(seed_hex: string): any;

/**
 * decode_address: validate and extract spend/view public keys from an address string.
 * Returns `{spend: hex, view: hex, intPaymentId: null}`.
 * Matches `Cn.decode_address(address)`.
 */
export function decode_address(address: string): any;

/**
 * derive_public_key: base_pub + derivation_to_scalar(derivation, index) × B.
 * Matches `CnNativeBride.derive_public_key(derivation, index, pub)`.
 */
export function derive_public_key(derivation_hex: string, out_index: number, base_pub_hex: string): string;

/**
 * derive_secret_key: sc_add(base_sec, derivation_to_scalar(derivation, index)).
 * Matches `CnNativeBride.derive_secret_key(derivation, index, sec)`.
 */
export function derive_secret_key(derivation_hex: string, out_index: number, base_sec_hex: string): string;

/**
 * ge_add: point_a + point_b (Edwards addition).
 */
export function ge_add(a_hex: string, b_hex: string): string;

/**
 * ge_frombytes_vartime: validate and canonicalise a compressed Edwards point.
 */
export function ge_frombytes_vartime(point_hex: string): string;

/**
 * ge_mul8: multiply point by cofactor 8.
 */
export function ge_mul8(point_hex: string): string;

/**
 * ge_p3_tobytes: alias for ge_tobytes.
 */
export function ge_p3_tobytes(point_hex: string): string;

/**
 * ge_scalarmult: point × scalar.
 */
export function ge_scalarmult(point_hex: string, scalar_hex: string): string;

/**
 * ge_scalarmult_base: scalar × base point.  Returns compressed public key hex.
 * Also serves as `sec_key_to_pub` — matches nacl.ll.ge_scalarmult_base behaviour.
 */
export function ge_scalarmult_base(scalar_hex: string): string;

/**
 * ge_tobytes / ge_p3_tobytes: returns the compressed point (validates it is on curve).
 */
export function ge_tobytes(point_hex: string): string;

/**
 * generate_key_derivation: 8 × (sec_scalar × pub_point).
 * Matches `CnNativeBride.generate_key_derivation(pub, sec)`.
 */
export function generate_key_derivation(pub_hex: string, sec_hex: string): string;

/**
 * generate_keys: sec = sc_reduce32(seed), pub = ge_scalarmult_base(sec).
 * Returns `{sec: hex, pub: hex}`.  Matches `Cn.generate_keys(seed)`.
 */
export function generate_keys(seed_hex: string): any;

/**
 * hash_to_scalar: cn_fast_hash then sc_reduce32.
 * Matches `Cn.hash_to_scalar(hex)` in Cn.ts.
 */
export function hash_to_scalar(data_hex: string): string;

/**
 * sc_0: returns a zero scalar (32 zero bytes as hex).
 */
export function sc_0(): string;

/**
 * sc_add: (a + b) mod l.
 */
export function sc_add(a_hex: string, b_hex: string): string;

/**
 * sc_check: returns true if the scalar is canonical (< group order l).
 */
export function sc_check(hex: string): boolean;

/**
 * sc_mulsub: (c - a*b) mod l.
 */
export function sc_mulsub(a_hex: string, b_hex: string, c_hex: string): string;

/**
 * sc_reduce32: reduce a 32-byte scalar mod the Ed25519 group order.
 */
export function sc_reduce32(hex: string): string;

/**
 * sc_sub: (a - b) mod l.
 */
export function sc_sub(a_hex: string, b_hex: string): string;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly cn_fast_hash: (a: number, b: number) => [number, number, number, number];
    readonly create_address: (a: number, b: number) => [number, number, number];
    readonly decode_address: (a: number, b: number) => [number, number, number];
    readonly derive_public_key: (a: number, b: number, c: number, d: number, e: number) => [number, number, number, number];
    readonly derive_secret_key: (a: number, b: number, c: number, d: number, e: number) => [number, number, number, number];
    readonly ge_add: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly ge_frombytes_vartime: (a: number, b: number) => [number, number, number, number];
    readonly ge_mul8: (a: number, b: number) => [number, number, number, number];
    readonly ge_p3_tobytes: (a: number, b: number) => [number, number, number, number];
    readonly ge_scalarmult: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly ge_scalarmult_base: (a: number, b: number) => [number, number, number, number];
    readonly generate_key_derivation: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly generate_keys: (a: number, b: number) => [number, number, number];
    readonly hash_to_scalar: (a: number, b: number) => [number, number, number, number];
    readonly sc_0: () => [number, number];
    readonly sc_add: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly sc_check: (a: number, b: number) => [number, number, number];
    readonly sc_mulsub: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number, number];
    readonly sc_reduce32: (a: number, b: number) => [number, number, number, number];
    readonly sc_sub: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly ge_tobytes: (a: number, b: number) => [number, number, number, number];
    readonly __wbindgen_malloc: (a: number, b: number) => number;
    readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
    readonly __wbindgen_externrefs: WebAssembly.Table;
    readonly __externref_table_dealloc: (a: number) => void;
    readonly __wbindgen_free: (a: number, b: number, c: number) => void;
    readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
 * Instantiates the given `module`, which can either be bytes or
 * a precompiled `WebAssembly.Module`.
 *
 * @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
 *
 * @returns {InitOutput}
 */
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
 * If `module_or_path` is {RequestInfo} or {URL}, makes a request and
 * for everything else, calls `WebAssembly.instantiate` directly.
 *
 * @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
 *
 * @returns {Promise<InitOutput>}
 */
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
