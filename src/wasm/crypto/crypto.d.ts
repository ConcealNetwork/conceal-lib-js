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
