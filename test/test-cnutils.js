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
    const upper = cnutils.hextobin("DEADBEEF");
    const ok = cnutils.bintohex(upper) === "deadbeef";
    log(`hextobin accepts uppercase hex: ${ok ? "PASS" : "FAIL"}`, ok);
  } catch (e) {
    log(`hextobin uppercase check failed: ${e}`, false);
  }

  try {
    const invalidCases = [
      "zz",
      "2x",
      "deadbeef2",
      "0xdeadbeef",
      "0XDEADBEEF",
      "de ad be ef",
      123,
      null,
    ];
    const ok = invalidCases.every((value) => {
      try {
        cnutils.hextobin(value);
        return false;
      } catch (_e) {
        return true;
      }
    });
    const emptyOk = cnutils.hextobin("").length === 0;
    log(
      `hextobin rejects invalid hex (${ok && emptyOk ? "PASS" : "FAIL"})`,
      ok && emptyOk,
    );
  } catch (e) {
    log(`hextobin invalid-hex check failed: ${e}`, false);
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
    // Numeric negatives hit the sign check after integer validation.
    const numericCases = [-5, -1];
    const numericOk = numericCases.every((value) => {
      let encodeThrew = false;
      let termThrew = false;
      try {
        cnutils.encode_varint(value);
      } catch (e) {
        encodeThrew =
          e instanceof Error && e.message === "varint cannot be negative";
      }
      try {
        cnutils.encode_varint_term(value);
      } catch (e) {
        termThrew =
          e instanceof Error && e.message === "varint cannot be negative";
      }
      return encodeThrew && termThrew;
    });
    // String negatives fail the /^\d+$/ format check before JSBigInt.
    const stringCases = ["-5", "-1"];
    const stringOk = stringCases.every((value) => {
      let encodeThrew = false;
      let termThrew = false;
      try {
        cnutils.encode_varint(value);
      } catch (e) {
        encodeThrew =
          e instanceof Error &&
          e.message === "varint input must be a non-negative integer";
      }
      try {
        cnutils.encode_varint_term(value);
      } catch (e) {
        termThrew =
          e instanceof Error &&
          e.message === "varint input must be a non-negative integer";
      }
      return encodeThrew && termThrew;
    });
    const ok = numericOk && stringOk;
    log(`encode_varint rejects negatives: ${ok ? "PASS" : "FAIL"}`, ok);
  } catch (e) {
    log(`encode_varint negative check failed: ${e}`, false);
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
    const ok = cnutils.h2d("0100000000000000") === 1;
    log(`h2d(0100…00) === 1: ${ok ? "PASS" : "FAIL"}`, ok);
  } catch (e) {
    log(`h2d happy path failed: ${e}`, false);
  }

  try {
    const invalidCases = [
      `2x${"0".repeat(14)}`,
      "zz".repeat(8),
      "abcd",
      "0100000000000000ff", // longer than 16 — old code truncated silently
      123,
      null,
    ];
    const ok = invalidCases.every((value) => {
      try {
        cnutils.h2d(value);
        return false;
      } catch {
        return true;
      }
    });
    log(`h2d rejects invalid hex: ${ok ? "PASS" : "FAIL"}`, ok);
  } catch (e) {
    log(`h2d invalid-hex check failed: ${e}`, false);
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

  // ── validation hardening: swapEndian throws on invalid input ─────────────
  try {
    let typeError = false;
    let oddLength = false;
    let nonHex = false;
    try {
      cnutils.swapEndian(123);
    } catch (e) {
      typeError = e instanceof TypeError;
    }
    try {
      cnutils.swapEndian("aabbccd");
    } catch (e) {
      oddLength =
        e instanceof Error &&
        !(e instanceof TypeError) &&
        e.message === "Hex string has invalid length!";
    }
    try {
      cnutils.swapEndian("aazz");
    } catch (e) {
      nonHex =
        e instanceof Error &&
        !(e instanceof TypeError) &&
        e.message === "Invalid hex string";
    }
    const ok = typeError && oddLength && nonHex;
    log(`swapEndian rejects invalid input: ${ok ? "PASS" : "FAIL"}`, ok);
  } catch (e) {
    log(`swapEndian validation check failed: ${e}`, false);
  }

  // ── validation hardening: d2h / d2s / d2b reject negative or fractional ──
  try {
    const cases = [
      () => cnutils.d2h(-1),
      () => cnutils.d2h("-5"),
      () => cnutils.d2h("1.5"),
      () => cnutils.d2h(undefined),
      () => cnutils.d2s(-5),
      () => cnutils.d2s("-1"),
      () => cnutils.d2b(-123),
      () => cnutils.d2b("-1"),
      () => cnutils.d2b("2.5"),
    ];
    const ok = cases.every((fn) => {
      try {
        fn();
        return false;
      } catch (e) {
        return e instanceof Error;
      }
    });
    log(
      `d2h/d2s/d2b reject negative or fractional input: ${ok ? "PASS" : "FAIL"}`,
      ok,
    );
  } catch (e) {
    log(`d2h/d2s/d2b validation check failed: ${e}`, false);
  }

  // ── validation hardening: d2h / d2s cap values at the 2^256 boundary ─────
  try {
    const max256Hex = "f".repeat(64);
    const below = (2n ** 256n - 1n).toString();
    const at = (2n ** 256n).toString();
    const above = (2n ** 256n + 1n).toString();

    let belowOk = false;
    try {
      belowOk =
        cnutils.d2h(below) === max256Hex && cnutils.d2s(below) === max256Hex;
    } catch {}

    let atThrew = false;
    try {
      cnutils.d2h(at);
    } catch (e) {
      atThrew =
        e instanceof Error &&
        !(e instanceof TypeError) &&
        /2\^256/.test(e.message);
    }
    let aboveThrew = false;
    try {
      cnutils.d2s(above);
    } catch (e) {
      aboveThrew =
        e instanceof Error &&
        !(e instanceof TypeError) &&
        /2\^256/.test(e.message);
    }

    const ok = belowOk && atThrew && aboveThrew;
    log(`d2h/d2s reject values ≥ 2^256: ${ok ? "PASS" : "FAIL"}`, ok);
  } catch (e) {
    log(`d2h/d2s 2^256 boundary check failed: ${e}`, false);
  }

  // ── validation hardening: d2s rejects undefined / null with a TypeError ──
  try {
    const cases = [undefined, null];
    const ok = cases.every((value) => {
      try {
        cnutils.d2s(value);
        return false;
      } catch (e) {
        return e instanceof TypeError && /d2s expects/.test(e.message);
      }
    });
    log(
      `d2s rejects undefined/null with TypeError: ${ok ? "PASS" : "FAIL"}`,
      ok,
    );
  } catch (e) {
    log(`d2s undefined/null check failed: ${e}`, false);
  }

  // ── validation hardening: h2d rejects values above MAX_SAFE_INTEGER ──────
  try {
    let allF = true;
    try {
      cnutils.h2d("ffffffffffffffff");
      allF = false;
    } catch {}
    let pow53 = true;
    try {
      cnutils.h2d("0000000000002000");
      pow53 = false;
    } catch {}
    const boundaryOk = cnutils.h2d("ffffffffffff0f00") === 4503599627370495;
    const ok = allF && pow53 && boundaryOk;
    log(
      `h2d rejects values above MAX_SAFE_INTEGER: ${ok ? "PASS" : "FAIL"}`,
      ok,
    );
  } catch (e) {
    log(`h2d overflow check failed: ${e}`, false);
  }

  // ── validation hardening: decompose rejects negative / fractional / junk ─
  try {
    const cases = [-123, "-123", "1.5", 1.5, "12a3", "", null, undefined];
    const ok = cases.every((value) => {
      try {
        cnutils.decompose_amount_into_digits(value);
        return false;
      } catch (e) {
        return e instanceof Error;
      }
    });
    log(
      `decompose_amount_into_digits rejects invalid amounts: ${
        ok ? "PASS" : "FAIL"
      }`,
      ok,
    );
  } catch (e) {
    log(`decompose_amount_into_digits validation check failed: ${e}`, false);
  }

  // ── validation hardening: varint encoders reject undefined / fractional ──
  try {
    const cases = [undefined, null, Number.NaN, 1.5, "1.5", "1e5", "abc"];
    const ok = cases.every((value) => {
      let encodeThrew = false;
      let termThrew = false;
      try {
        cnutils.encode_varint(value);
      } catch (e) {
        encodeThrew = e instanceof Error;
      }
      try {
        cnutils.encode_varint_term(value);
      } catch (e) {
        termThrew = e instanceof Error;
      }
      return encodeThrew && termThrew;
    });
    log(
      `encode_varint/term reject undefined, null, NaN, fractional: ${
        ok ? "PASS" : "FAIL"
      }`,
      ok,
    );
  } catch (e) {
    log(`varint validation check failed: ${e}`, false);
  }

  // ── item 6: validate format BEFORE JSBigInt — "1.5"/"1e5" are rejected by ──
  // ── the regex, not silently truncated to 1/100000 by JSBigInt             ──
  try {
    const formatCases = [
      {
        input: "1.5",
        expectMsg: "varint input must be a non-negative integer",
      },
      {
        input: "1e5",
        expectMsg: "varint input must be a non-negative integer",
      },
    ];
    const ok = formatCases.every(({ input, expectMsg }) => {
      let encodeOk = false;
      let termOk = false;
      try {
        cnutils.encode_varint(input);
      } catch (e) {
        encodeOk = e instanceof Error && e.message === expectMsg;
      }
      try {
        cnutils.encode_varint_term(input);
      } catch (e) {
        termOk = e instanceof Error && e.message === expectMsg;
      }
      return encodeOk && termOk;
    });
    log(
      `encode_varint/term reject "1.5"/"1e5" before JSBigInt parse: ${ok ? "PASS" : "FAIL"}`,
      ok,
    );
  } catch (e) {
    log(`varint format-before-JSBigInt check failed: ${e}`, false);
  }

  // ── curve (nacl.ll) vs crypto WASM ────────────────────────────────────────
  try {
    const reduced = wasmCrypto.sc_reduce32(SEED);
    const pubNacl = cnutils.sec_key_to_pub(reduced);
    const keys = wasmCrypto.generate_keys(SEED);
    const ok = pubNacl === keys.pub;
    log(`sec_key_to_pub === generate_keys.pub: ${ok ? "PASS" : "FAIL"}`, ok);

    const twice = cnutils.ge_neg(cnutils.ge_neg(pubNacl));
    const roundTrip = twice === pubNacl;
    log(`ge_neg(ge_neg(P)) === P: ${roundTrip ? "PASS" : "FAIL"}`, roundTrip);
  } catch (e) {
    log(`sec_key_to_pub failed: ${e}`, false);
  }

  try {
    const invalidCases = ["z".repeat(64), "aa".repeat(31), 123, null];
    const ok = invalidCases.every((value) => {
      try {
        cnutils.ge_neg(value);
        return false;
      } catch {
        return true;
      }
    });
    log(`ge_neg rejects invalid hex: ${ok ? "PASS" : "FAIL"}`, ok);
  } catch (e) {
    log(`ge_neg invalid-hex check failed: ${e}`, false);
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
