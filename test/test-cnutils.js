import wasmCrypto from "#cnutils-wasm";
import * as cnutils from "../src/js/cnutils.js";
import { keccak_256, sha3_384 } from "../src/js/tiers/sha3.js";

const KECCAK_EMPTY =
  "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470";

const SEED = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

const SPEND_PUB =
  "130ae82201d7072e6fbfc0a1884fb54636554d14945b799125cf7ce38d477f51";

/** Wallet `allowedExceptions` joined content (allowedPages.ts parity). */
const ALLOWED_EXCEPTIONS_CONTENT =
  "send%3Faddress%3Dccx7V4LeUXy2eZ9waDXgsLS7Uc11e2CpNSCWVdxEqSRFAm6P6NQhSb7XMG1D6VAZKmJeaJP37WYQg84zbNrPduTX2whZ5pacfj";

const SHA3_384_ALLOWED_EXCEPTIONS =
  "8f59c6a2a7a81c7a22f46c9bbe2b5bbc014af6295d8c49639d686d1aa1b5b3cfb4736dc7b533eac4462601fc0d0f5620";

/**
 * @param {(msg: string, ok: boolean) => void} log
 */
export async function runCnutilsTests(log) {
  // ── sha3 / keccak_256 ─────────────────────────────────────────────────────
  try {
    const empty = keccak_256(new Uint8Array(0));
    const ok = empty === KECCAK_EMPTY;
    log(`keccak_256(empty) known vector: ${ok ? "PASS" : "FAIL"}`, ok);
  } catch (e) {
    log(`keccak_256(empty) failed: ${e}`, false);
  }

  try {
    const fromBytes = keccak_256(cnutils.hextobin(SEED));
    const fromCn = cnutils.cn_fast_hash(SEED);
    const ok = fromBytes === fromCn;
    log(`cn_fast_hash === keccak_256(hextobin): ${ok ? "PASS" : "FAIL"}`, ok);
  } catch (e) {
    log(`cn_fast_hash / keccak_256 parity failed: ${e}`, false);
  }

  try {
    const digest = sha3_384(ALLOWED_EXCEPTIONS_CONTENT);
    const ok =
      digest === SHA3_384_ALLOWED_EXCEPTIONS &&
      digest.length === 96 &&
      digest === digest.toLowerCase();
    log(`sha3_384(allowedExceptions): ${ok ? "PASS" : "FAIL"}`, ok);
  } catch (e) {
    log(`sha3_384 wallet vector failed: ${e}`, false);
  }

  try {
    const fromString = sha3_384("test");
    const fromBytes = sha3_384(new TextEncoder().encode("test"));
    const ok = fromString === fromBytes && fromString.length === 96;
    log(`sha3_384 string === UTF-8 bytes: ${ok ? "PASS" : "FAIL"}`, ok);
  } catch (e) {
    log(`sha3_384 input types failed: ${e}`, false);
  }

  try {
    const jsHash = cnutils.cn_fast_hash(SEED);
    const wasmHash = wasmCrypto.cn_fast_hash(SEED);
    const ok = jsHash === wasmHash;
    log(
      "cnutils.cn_fast_hash === crypto.cn_fast_hash (WASM): " +
        (ok ? "PASS" : "FAIL"),
      ok,
    );
  } catch (e) {
    log(`cn_fast_hash WASM cross-check failed: ${e}`, false);
  }

  // ── hex helpers ───────────────────────────────────────────────────────────
  try {
    const bin = cnutils.hextobin("deadbeef");
    const ok =
      bin.length === 4 &&
      bin[0] === 0xde &&
      cnutils.bintohex(bin) === "deadbeef";
    log(`hextobin / bintohex round-trip: ${ok ? "PASS" : "FAIL"}`, ok);
  } catch (e) {
    log(`hextobin / bintohex failed: ${e}`, false);
  }

  try {
    const ok = cnutils.swapEndian("aabbcc") === "ccbbaa";
    log(`swapEndian: ${ok ? "PASS" : "FAIL"}`, ok);
  } catch (e) {
    log(`swapEndian failed: ${e}`, false);
  }

  try {
    const ok = cnutils.valid_hex("0123abcd") && !cnutils.valid_hex("0123abcg");
    log(`valid_hex: ${ok ? "PASS" : "FAIL"}`, ok);
  } catch (e) {
    log(`valid_hex failed: ${e}`, false);
  }

  try {
    const ok =
      cnutils.hex_xor("ff00", "0f0f") === "f00f" &&
      cnutils.hex_xor("aa", "aa") === "00";
    log(`hex_xor: ${ok ? "PASS" : "FAIL"}`, ok);
  } catch (e) {
    log(`hex_xor failed: ${e}`, false);
  }

  // ── integers / varint ─────────────────────────────────────────────────────
  try {
    const ok =
      cnutils.encode_varint(0) === "00" && cnutils.encode_varint(127) === "7f";
    log(`encode_varint(0, 127): ${ok ? "PASS" : "FAIL"}`, ok);
  } catch (e) {
    log(`encode_varint failed: ${e}`, false);
  }

  try {
    const scalar8 = cnutils.d2s(8);
    const ok =
      typeof scalar8 === "string" &&
      scalar8.length === 64 &&
      cnutils.valid_hex(scalar8);
    log(`d2s(8) → 64-char hex: ${ok ? "PASS" : "FAIL"}`, ok);
  } catch (e) {
    log(`d2s failed: ${e}`, false);
  }

  try {
    const digits = cnutils.decompose_amount_into_digits("12345");
    const ok =
      digits.length === 5 &&
      digits[0].toString() === "10000" &&
      digits[4].toString() === "5";
    log(`decompose_amount_into_digits(12345): ${ok ? "PASS" : "FAIL"}`, ok);
  } catch (e) {
    log(`decompose_amount_into_digits failed: ${e}`, false);
  }

  // ── curve (nacl.ll) vs crypto WASM ────────────────────────────────────────
  try {
    const reduced = wasmCrypto.sc_reduce32(SEED);
    const pubNacl = cnutils.sec_key_to_pub(reduced);
    const keys = wasmCrypto.generate_keys(SEED);
    const ok = pubNacl === keys.pub;
    log(`sec_key_to_pub === generate_keys.pub: ${ok ? "PASS" : "FAIL"}`, ok);
  } catch (e) {
    log(`sec_key_to_pub failed: ${e}`, false);
  }

  try {
    const deriv = wasmCrypto.generate_key_derivation(SPEND_PUB, SEED);
    const cnScalar = cnutils.derivation_to_scalar(deriv, 0);
    const wasmScalar = wasmCrypto.hash_to_scalar(
      deriv + cnutils.encode_varint(0),
    );
    const ok = cnScalar === wasmScalar;
    log(
      `derivation_to_scalar vs WASM hash_to_scalar: ${ok ? "PASS" : "FAIL"}`,
      ok,
    );
  } catch (e) {
    log(`derivation_to_scalar failed: ${e}`, false);
  }

  // ── RCT ECDH (WASM scalar ops) ────────────────────────────────────────────
  try {
    const key = wasmCrypto.hash_to_scalar(SEED);
    const plain = {
      mask: wasmCrypto.sc_0(),
      amount: wasmCrypto.sc_0(),
    };
    const enc = cnutils.encode_rct_ecdh(plain, key);
    const dec = cnutils.decode_rct_ecdh(enc, key);
    const ok = dec.mask === plain.mask && dec.amount === plain.amount;
    log(
      `encode_rct_ecdh / decode_rct_ecdh round-trip: ${ok ? "PASS" : "FAIL"}`,
      ok,
    );
  } catch (e) {
    log(`rct ecdh round-trip failed: ${e}`, false);
  }

  // ── hash_to_ec32 / hash_to_ec160 (needs recent crypto WASM build) ─────────
  if (typeof wasmCrypto.hash_to_ec32 === "function") {
    try {
      const Pb = wasmCrypto.hash_to_ec32(SPEND_PUB);
      const ok =
        typeof Pb === "string" && Pb.length === 64 && cnutils.valid_hex(Pb);
      log(`hash_to_ec32 → 64-char point: ${ok ? "PASS" : "FAIL"}`, ok);
    } catch (e) {
      log(`hash_to_ec32 failed: ${e}`, false);
    }
  } else {
    log("hash_to_ec32: SKIP (run npm run build:crypto)", true);
  }

  if (typeof wasmCrypto.hash_to_ec160 === "function") {
    try {
      const p3 = wasmCrypto.hash_to_ec160(SPEND_PUB);
      const ok =
        typeof p3 === "string" &&
        p3.length === cnutils.STRUCT_SIZES.GE_P3 * 2 &&
        cnutils.valid_hex(p3);
      log(`hash_to_ec160 → GE_P3 hex: ${ok ? "PASS" : "FAIL"}`, ok);
    } catch (e) {
      log(`hash_to_ec160 failed: ${e}`, false);
    }
  } else {
    log("hash_to_ec160: SKIP (run npm run build:crypto)", true);
  }

  try {
    cnutils.cn_fast_hash("abc");
    log("cn_fast_hash odd-length hex should throw", false);
  } catch (_e) {
    log("cn_fast_hash rejects invalid hex: PASS", true);
  }
}
