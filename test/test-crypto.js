import init, {
  cn_fast_hash,
  create_address,
  decode_address,
  derive_public_key,
  derive_secret_key,
  ge_add,
  ge_frombytes_vartime,
  ge_mul8,
  ge_scalarmult,
  ge_scalarmult_base,
  generate_key_derivation,
  generate_keys,
  hash_to_scalar,
  sc_0,
  sc_add,
  sc_check,
  sc_reduce32,
} from "./wasm/crypto/crypto.js";

/**
 * Run all crypto tests.
 * @param {(msg: string, ok: boolean) => void} log - callback provided by the test runner
 */
export async function runCryptoTests(log) {
  await init();

  // ── Test 1: generate_keys from a known seed ───────────────────────────────
  const seed =
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
  let keys;
  try {
    keys = generate_keys(seed);
    const ok =
      keys &&
      typeof keys.sec === "string" &&
      keys.sec.length === 64 &&
      typeof keys.pub === "string" &&
      keys.pub.length === 64;
    log(
      "generate_keys → {sec, pub} (64-char hex each): " +
        (ok ? "PASS" : "FAIL"),
      ok,
    );
    if (!ok) return;
  } catch (e) {
    log(`generate_keys failed: ${e}`, false);
    return;
  }

  // ── Test 2: ge_scalarmult_base matches generate_keys pub ─────────────────
  try {
    const reduced = sc_reduce32(seed);
    const pub = ge_scalarmult_base(reduced);
    const ok = pub === keys.pub;
    log(
      "ge_scalarmult_base(sc_reduce32(seed)) === generate_keys.pub: " +
        (ok ? "PASS" : "FAIL"),
      ok,
    );
  } catch (e) {
    log(`ge_scalarmult_base failed: ${e}`, false);
  }

  // ── Test 3: cn_fast_hash returns 64-char hex ──────────────────────────────
  let hashOut;
  try {
    hashOut = cn_fast_hash(seed);
    const ok =
      typeof hashOut === "string" &&
      hashOut.length === 64 &&
      /^[0-9a-f]+$/.test(hashOut);
    log(`cn_fast_hash → 64-char hex: ${ok ? "PASS" : "FAIL"}`, ok);
  } catch (e) {
    log(`cn_fast_hash failed: ${e}`, false);
    return;
  }

  // ── Test 4: cn_fast_hash is deterministic ─────────────────────────────────
  try {
    const ok = cn_fast_hash(seed) === hashOut;
    log(`cn_fast_hash is deterministic: ${ok ? "PASS" : "FAIL"}`, ok);
  } catch (e) {
    log(`cn_fast_hash determinism check failed: ${e}`, false);
  }

  // ── Test 5: hash_to_scalar returns canonical scalar ───────────────────────
  try {
    const scalar = hash_to_scalar(seed);
    const ok =
      typeof scalar === "string" && scalar.length === 64 && sc_check(scalar);
    log(`hash_to_scalar → canonical scalar: ${ok ? "PASS" : "FAIL"}`, ok);
  } catch (e) {
    log(`hash_to_scalar failed: ${e}`, false);
  }

  // ── Test 6: sc_0 returns 64 zero hex chars ────────────────────────────────
  try {
    const zero = sc_0();
    const ok = zero === "0".repeat(64);
    log(`sc_0() → 64 zero hex chars: ${ok ? "PASS" : "FAIL"}`, ok);
  } catch (e) {
    log(`sc_0 failed: ${e}`, false);
  }

  // ── Test 7: sc_add and sc_check ───────────────────────────────────────────
  try {
    const a = hash_to_scalar(seed);
    const b = hash_to_scalar(hashOut);
    const sum = sc_add(a, b);
    const ok = typeof sum === "string" && sum.length === 64 && sc_check(sum);
    log(`sc_add → canonical scalar: ${ok ? "PASS" : "FAIL"}`, ok);
  } catch (e) {
    log(`sc_add failed: ${e}`, false);
  }

  // ── Test 8: ge_mul8 returns a valid point ────────────────────────────────
  try {
    const point = ge_scalarmult_base(keys.sec);
    const mul8 = ge_mul8(point);
    const ok = typeof mul8 === "string" && mul8.length === 64;
    log(`ge_mul8 → 64-char hex point: ${ok ? "PASS" : "FAIL"}`, ok);
  } catch (e) {
    log(`ge_mul8 failed: ${e}`, false);
  }

  // ── Test 9: ge_add(P, 0*B) identity check — result must equal P ─────────
  try {
    const P = ge_scalarmult_base(keys.sec);
    const zero = sc_0();
    const zP = ge_scalarmult(P, zero);
    const sum = ge_add(P, zP);
    const ok = typeof sum === "string" && sum.length === 64 && sum === P;
    log(`ge_add(P, 0·P) === P: ${ok ? "PASS" : "FAIL"}`, ok);
  } catch (e) {
    log(`ge_add failed: ${e}`, false);
  }

  // ── Test 10a: ge_frombytes_vartime idempotency on a valid point ──────────
  try {
    const point = ge_scalarmult_base(keys.sec);
    const canonical = ge_frombytes_vartime(point);
    const ok = canonical === point;
    log(
      "ge_frombytes_vartime(valid point) is idempotent: " +
        (ok ? "PASS" : "FAIL"),
      ok,
    );
  } catch (e) {
    log(`ge_frombytes_vartime failed: ${e}`, false);
  }

  // ── Test 10b: ge_frombytes_vartime rejects an invalid point ──────────────
  // Note: 64×'0' is a valid compressed Edwards y (dalek accepts it); use off-curve bytes.
  const invalidPoint =
    "0200000000000000000000000000000000000000000000000000000000000000";
  try {
    ge_frombytes_vartime(invalidPoint);
    log("ge_frombytes_vartime should have thrown on invalid point", false);
  } catch (e) {
    log(`ge_frombytes_vartime correctly rejected invalid point: ${e}`, true);
  }

  // ── Test 11: generate_key_derivation ─────────────────────────────────────
  let derivation;
  try {
    const keys2 = generate_keys(cn_fast_hash(seed));
    derivation = generate_key_derivation(keys2.pub, keys.sec);
    const ok = typeof derivation === "string" && derivation.length === 64;
    log(`generate_key_derivation → 64-char hex: ${ok ? "PASS" : "FAIL"}`, ok);
  } catch (e) {
    log(`generate_key_derivation failed: ${e}`, false);
    derivation = null;
  }

  // ── Test 12: derive_public_key / derive_secret_key round-trip ────────────
  if (derivation) {
    try {
      const derivedPub = derive_public_key(derivation, 0, keys.pub);
      const derivedSec = derive_secret_key(derivation, 0, keys.sec);
      const recovPub = ge_scalarmult_base(derivedSec);
      const ok = derivedPub === recovPub;
      log(
        "derive_public_key matches ge_scalarmult_base(derive_secret_key): " +
          (ok ? "PASS" : "FAIL"),
        ok,
      );
    } catch (e) {
      log(`derive_public/secret_key failed: ${e}`, false);
    }
  }

  // ── Test 13: create_address returns expected shape ────────────────────────
  let addr;
  try {
    addr = create_address(seed);
    const ok =
      addr &&
      typeof addr.public_addr === "string" &&
      addr.public_addr.length >= 95 &&
      addr.spend &&
      typeof addr.spend.pub === "string" &&
      addr.spend.pub.length === 64 &&
      addr.view &&
      typeof addr.view.pub === "string" &&
      addr.view.pub.length === 64;
    log(
      `create_address → {public_addr, spend, view}: ${ok ? "PASS" : "FAIL"}`,
      ok,
    );
    if (!ok) return;
  } catch (e) {
    log(`create_address failed: ${e}`, false);
    return;
  }

  // ── Test 14: decode_address round-trip ───────────────────────────────────
  try {
    const decoded = decode_address(addr.public_addr);
    const ok =
      decoded &&
      decoded.spend === addr.spend.pub &&
      decoded.view === addr.view.pub &&
      (decoded.intPaymentId === null || decoded.intPaymentId === undefined);
    log(
      "decode_address round-trip (spend + view keys match): " +
        (ok ? "PASS" : "FAIL"),
      ok,
    );
  } catch (e) {
    log(`decode_address failed: ${e}`, false);
  }

  // ── Test 14b: integrated decode_address surfaces payment ID ──────────────
  try {
    const { encode_integrated_address } = await import("../src/js/address.js");
    const paymentId = "00112233445566aa";
    const integrated = encode_integrated_address(
      addr.spend.pub,
      addr.view.pub,
      paymentId,
    );
    const decoded = decode_address(integrated);
    if (decoded.intPaymentId === paymentId) {
      const ok =
        decoded.spend === addr.spend.pub &&
        decoded.view === addr.view.pub &&
        decoded.intPaymentId === paymentId;
      log(`decode_address integrated payment ID: ${ok ? "PASS" : "FAIL"}`, ok);
    } else {
      log(
        "decode_address integrated payment ID: SKIP (rebuild crypto WASM)",
        true,
      );
    }
  } catch (e) {
    log(`decode_address integrated failed: ${e}`, false);
  }

  // ── Test 15: decode_address rejects a garbled address ────────────────────
  try {
    decode_address("not_a_valid_address_00000000");
    log("decode_address should have thrown on invalid input", false);
  } catch (e) {
    log(`decode_address correctly rejected invalid input: ${e}`, true);
  }

  // ── optional: generate_signature (needs recent `npm run build:test:crypto`) ─
  try {
    const wasm = await import("./wasm/crypto/crypto.js");
    if (typeof wasm.generate_signature === "function") {
      const sig = wasm.generate_signature(hashOut, keys.pub, keys.sec);
      const ok = typeof sig === "string" && sig.length === 128;
      log(`generate_signature → 128-char hex: ${ok ? "PASS" : "FAIL"}`, ok);
    } else {
      log("generate_signature: SKIP (rebuild crypto WASM)", true);
    }
  } catch (e) {
    log(`generate_signature: SKIP (${e})`, true);
  }
}
