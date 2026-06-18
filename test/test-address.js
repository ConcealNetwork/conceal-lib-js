import * as address from "../src/js/address.js";
import * as base58 from "../src/js/base58.js";
import init, { create_address, decode_address } from "./wasm/crypto/crypto.js";

/**
 * `decode_address` reports a missing payment ID as `null` (no integrated id).
 * @param {unknown} value
 * @returns {boolean}
 */
function isNoPaymentId(value) {
  return value === null || value === undefined;
}

/**
 * Run all address-encoder tests.
 * @param {(msg: string, ok: boolean) => void} log - callback provided by the test runner
 */
export async function runAddressTests(log) {
  await init();

  // 32-byte seeds — must be exactly 64 hex chars (see test-crypto.js)
  const seeds = [
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
    "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "0f0e0d0c0b0a09080706050403020100ffeeddccbbaa99887766554433221100",
  ];

  // ── Parity (gold standard): encode_address === WASM public_addr ────────────
  for (const seed of seeds) {
    try {
      const keys = create_address(seed);
      const encoded = address.encode_address(keys.spend.pub, keys.view.pub);
      const ok = encoded === keys.public_addr;
      log(
        `encode_address parity (seed ${seed.slice(0, 8)}…): ${ok ? "PASS" : "FAIL"}`,
        ok,
      );
    } catch (e) {
      log(`encode_address parity (seed ${seed.slice(0, 8)}…) failed: ${e}`, false);
    }
  }

  // ── Round-trip plain: decode_address(encode_address(s, v)) ─────────────────
  try {
    const keys = create_address(seeds[0]);
    const encoded = address.encode_address(keys.spend.pub, keys.view.pub);
    const decoded = decode_address(encoded);
    const ok =
      decoded.spend === keys.spend.pub &&
      decoded.view === keys.view.pub &&
      isNoPaymentId(decoded.intPaymentId);
    log(`encode_address round-trip via decode_address: ${ok ? "PASS" : "FAIL"}`, ok);
  } catch (e) {
    log(`encode_address round-trip failed: ${e}`, false);
  }

  // ── Round-trip integrated ──────────────────────────────────────────────────
  // WASM `decode_address` decodes spend/view from an integrated address but does
  // not surface the payment ID (always reports `intPaymentId: null`). So assert
  // spend/view via WASM and independently confirm the embedded payment ID by
  // decoding the base58 ourselves.
  try {
    const keys = create_address(seeds[0]);
    const paymentId = "00112233445566aa";
    const encoded = address.encode_integrated_address(
      keys.spend.pub,
      keys.view.pub,
      paymentId,
    );
    const decoded = decode_address(encoded);
    const keysMatch =
      decoded.spend === keys.spend.pub && decoded.view === keys.view.pub;

    // Independently verify the embedded payment ID: prefix(varint) + spend(32) +
    // view(32) + paymentId(8) + checksum(4). Slice out the payment ID bytes.
    const raw = base58.decode(encoded);
    const prefixHex = "d5f501"; // encode_varint(INTEGRATED_ADDRESS_PREFIX)
    const idStart = prefixHex.length + 64 + 64;
    const idEnd = idStart + address.INTEGRATED_ID_SIZE * 2;
    const embeddedId = raw.slice(idStart, idEnd);
    const ok = keysMatch && embeddedId === paymentId;
    log(`encode_integrated_address round-trip: ${ok ? "PASS" : "FAIL"}`, ok);
  } catch (e) {
    log(`encode_integrated_address round-trip failed: ${e}`, false);
  }

  // ── base58 round-trip across varying lengths (incl. partial last blocks) ────
  try {
    const samples = [
      "00", // 1 byte → 2 chars (partial block)
      "ffff", // 2 bytes → 3 chars (partial block)
      "0011223344556677", // 8 bytes → one full block
      "0011223344556677aabb", // 10 bytes → full block + 2-byte partial
      "ca4a448c3fc4d04945da9fdf920976c05e9bbe3d8cebb1858ea44d587c5e63c3", // 32 bytes
      "abcdef0123456789abcdef0123456789abcdef0123", // 21 bytes → odd partial tail
    ];
    let allOk = true;
    for (const hex of samples) {
      const rt = base58.decode(base58.encode(hex));
      if (rt !== hex) {
        allOk = false;
        log(`base58 round-trip FAIL for len ${hex.length}: got ${rt}`, false);
      }
    }
    log(`base58 round-trip (varying lengths): ${allOk ? "PASS" : "FAIL"}`, allOk);
  } catch (e) {
    log(`base58 round-trip failed: ${e}`, false);
  }

  // ── base58 overflow / malleability boundary (UINT64_MAX = 2^64 - 1) ─────────
  try {
    const threw = (fn) => {
      try {
        fn();
        return false;
      } catch {
        return true;
      }
    };
    // Largest value representable in a full 8-byte block (2^64 - 1) must encode
    // AND round-trip — the overflow bound must not reject it.
    const maxBlock = "ffffffffffffffff";
    const maxRoundTrips = base58.decode(base58.encode(maxBlock)) === maxBlock;
    // An 11-char block above 2^64 ("zzzzzzzzzzz" = 58^11 - 1) must be rejected.
    const overMaxRejected = threw(() => base58.decode("zzzzzzzzzzz"));
    // Non-string and malformed-hex inputs must throw cleanly (not cryptic).
    const nonStringRejected = threw(() => base58.decode(null));
    const badHexRejected = threw(() => base58.encode("zz"));
    const oddHexRejected = threw(() => base58.encode("abc"));
    const ok =
      maxRoundTrips && overMaxRejected && nonStringRejected && badHexRejected && oddHexRejected;
    log(`base58 overflow/validation boundaries: ${ok ? "PASS" : "FAIL"}`, ok);
  } catch (e) {
    log(`base58 boundary test failed: ${e}`, false);
  }

  // ── Validation throws: encode_address with bad keys ─────────────────────────
  try {
    const good = "11".repeat(32); // valid 64-char hex key
    const threw = (fn) => {
      try {
        fn();
        return false;
      } catch {
        return true;
      }
    };
    const nonHex = threw(() => address.encode_address("z".repeat(64), good));
    const shortKey = threw(() => address.encode_address("ab", good));
    const longKey = threw(() => address.encode_address(`${good}00`, good));
    const badViewNonHex = threw(() => address.encode_address(good, "g".repeat(64)));
    const ok = nonHex && shortKey && longKey && badViewNonHex;
    log(`encode_address validation throws: ${ok ? "PASS" : "FAIL"}`, ok);
  } catch (e) {
    log(`encode_address validation test failed: ${e}`, false);
  }

  // ── Validation throws: encode_integrated_address with bad paymentId ─────────
  try {
    const good = "11".repeat(32);
    const threw = (fn) => {
      try {
        fn();
        return false;
      } catch {
        return true;
      }
    };
    const shortId = threw(() => address.encode_integrated_address(good, good, "0011"));
    const longId = threw(() =>
      address.encode_integrated_address(good, good, "00112233445566aabb"),
    );
    const nonHexId = threw(() =>
      address.encode_integrated_address(good, good, "zzzzzzzzzzzzzzzz"),
    );
    const ok = shortId && longId && nonHexId;
    log(`encode_integrated_address paymentId validation throws: ${ok ? "PASS" : "FAIL"}`, ok);
  } catch (e) {
    log(`encode_integrated_address validation test failed: ${e}`, false);
  }
}
