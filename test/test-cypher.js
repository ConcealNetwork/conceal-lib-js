import init, { chacha8, chacha12, chacha20 } from "./wasm/cypher/cypher.js";

/** @returns {Uint8Array} */
function randomBytes(n) {
  const buf = new Uint8Array(n);
  crypto.getRandomValues(buf);
  return buf;
}

/** @param {Uint8Array} a @param {Uint8Array} b @returns {boolean} */
function equal(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

/**
 * Run all cypher tests.
 * @param {(msg: string, ok: boolean) => void} log - callback provided by the test runner
 */
export async function runCypherTests(log) {
  await init();

  const key = randomBytes(32);
  const nonce = randomBytes(12);
  const plain = new TextEncoder().encode("concealjs chacha test vector 1234");

  // ── Test 1: chacha8 encrypt/decrypt round-trip ────────────────────────────
  try {
    const cipher = chacha8(key, nonce, plain);
    const recovered = chacha8(key, nonce, cipher);
    const ok = equal(recovered, plain);
    log("chacha8 encrypt→decrypt round-trip: " + (ok ? "PASS" : "FAIL"), ok);
  } catch (e) {
    log("chacha8 round-trip failed: " + e, false);
  }

  // ── Test 2: chacha8 ciphertext differs from plaintext ────────────────────
  try {
    const cipher = chacha8(key, nonce, plain);
    const ok = !equal(cipher, plain);
    log("chacha8 ciphertext ≠ plaintext: " + (ok ? "PASS" : "FAIL"), ok);
  } catch (e) {
    log("chacha8 ciphertext check failed: " + e, false);
  }

  // ── Test 3: chacha8 is deterministic ─────────────────────────────────────
  try {
    const c1 = chacha8(key, nonce, plain);
    const c2 = chacha8(key, nonce, plain);
    const ok = equal(c1, c2);
    log("chacha8 is deterministic: " + (ok ? "PASS" : "FAIL"), ok);
  } catch (e) {
    log("chacha8 determinism check failed: " + e, false);
  }

  // ── Test 4: chacha8 different nonce → different ciphertext ───────────────
  try {
    const nonce2 = randomBytes(12);
    const c1 = chacha8(key, nonce, plain);
    const c2 = chacha8(key, nonce2, plain);
    const ok = !equal(c1, c2);
    log(
      "chacha8 different nonce → different ciphertext: " +
        (ok ? "PASS" : "FAIL"),
      ok,
    );
  } catch (e) {
    log("chacha8 nonce sensitivity check failed: " + e, false);
  }

  // ── Test 5: chacha8 rejects wrong key length ──────────────────────────────
  try {
    chacha8(randomBytes(16), nonce, plain);
    log("chacha8 should have rejected 16-byte key", false);
  } catch (e) {
    log("chacha8 correctly rejected 16-byte key: " + e, true);
  }

  // ── Test 6: chacha8 rejects wrong nonce length ───────────────────────────
  try {
    chacha8(key, randomBytes(8), plain);
    log("chacha8 should have rejected 8-byte nonce", false);
  } catch (e) {
    log("chacha8 correctly rejected 8-byte nonce: " + e, true);
  }

  // ── Test 7: chacha12 encrypt/decrypt round-trip ───────────────────────────
  try {
    const cipher = chacha12(key, nonce, plain);
    const recovered = chacha12(key, nonce, cipher);
    const ok = equal(recovered, plain);
    log("chacha12 encrypt→decrypt round-trip: " + (ok ? "PASS" : "FAIL"), ok);
  } catch (e) {
    log("chacha12 round-trip failed: " + e, false);
  }

  // ── Test 8: chacha12 ciphertext differs from plaintext ───────────────────
  try {
    const cipher = chacha12(key, nonce, plain);
    const ok = !equal(cipher, plain);
    log("chacha12 ciphertext ≠ plaintext: " + (ok ? "PASS" : "FAIL"), ok);
  } catch (e) {
    log("chacha12 ciphertext check failed: " + e, false);
  }

  // ── Test 9: chacha8 and chacha12 produce different outputs ───────────────
  try {
    const c8 = chacha8(key, nonce, plain);
    const c12 = chacha12(key, nonce, plain);
    const ok = !equal(c8, c12);
    log("chacha8 ≠ chacha12 for same inputs: " + (ok ? "PASS" : "FAIL"), ok);
  } catch (e) {
    log("chacha8 vs chacha12 comparison failed: " + e, false);
  }

  // ── Test 10: chacha12 rejects wrong key length ───────────────────────────
  try {
    chacha12(randomBytes(16), nonce, plain);
    log("chacha12 should have rejected 16-byte key", false);
  } catch (e) {
    log("chacha12 correctly rejected 16-byte key: " + e, true);
  }

  // ── Test 11: chacha12 different nonce → different ciphertext ─────────────
  try {
    const nonce2 = randomBytes(12);
    const c1 = chacha12(key, nonce, plain);
    const c2 = chacha12(key, nonce2, plain);
    const ok = !equal(c1, c2);
    log(
      "chacha12 different nonce → different ciphertext: " +
        (ok ? "PASS" : "FAIL"),
      ok,
    );
  } catch (e) {
    log("chacha12 nonce sensitivity check failed: " + e, false);
  }

  // ── Test 12: chacha12 rejects wrong nonce length ──────────────────────────
  try {
    chacha12(key, randomBytes(8), plain);
    log("chacha12 should have rejected 8-byte nonce", false);
  } catch (e) {
    log("chacha12 correctly rejected 8-byte nonce: " + e, true);
  }

  // ── Test 13: chacha20 encrypt/decrypt round-trip ─────────────────────────
  try {
    const cipher = chacha20(key, nonce, plain);
    const recovered = chacha20(key, nonce, cipher);
    const ok = equal(recovered, plain);
    log("chacha20 encrypt→decrypt round-trip: " + (ok ? "PASS" : "FAIL"), ok);
  } catch (e) {
    log("chacha20 round-trip failed: " + e, false);
  }

  // ── Test 14: chacha12 and chacha20 produce different outputs ─────────────
  try {
    const c12 = chacha12(key, nonce, plain);
    const c20 = chacha20(key, nonce, plain);
    const ok = !equal(c12, c20);
    log("chacha12 ≠ chacha20 for same inputs: " + (ok ? "PASS" : "FAIL"), ok);
  } catch (e) {
    log("chacha12 vs chacha20 comparison failed: " + e, false);
  }
}
