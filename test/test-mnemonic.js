import { mn_decode, mn_encode, mn_random } from "../src/js/mnemonic.js";

const LANGUAGES = [
  { name: "english", expectedWords: 25 },
  { name: "spanish", expectedWords: 25 },
  { name: "portuguese", expectedWords: 25 },
  { name: "japanese", expectedWords: 25 },
  { name: "electrum", expectedWords: 24 },
];

/**
 * Run all mnemonic tests.
 * @param {(msg: string, ok: boolean) => void} log - callback provided by the test runner
 */
export async function runMnemonicTests(log) {
  // ── Test 1: mn_random(256) returns a 64-char hex string ─────────────────
  let entropy;
  try {
    entropy = mn_random(256);
    const ok =
      typeof entropy === "string" &&
      entropy.length === 64 &&
      /^[0-9a-f]+$/.test(entropy);
    log(
      "mn_random(256) → 64-char hex: " +
        (ok ? "PASS" : `FAIL — got: ${entropy}`),
      ok,
    );
  } catch (e) {
    log(`mn_random(256) failed: ${e}`, false);
    return;
  }

  // ── Test 2: mn_random with invalid bits rejected ─────────────────────────
  try {
    mn_random(100);
    log("mn_random(100) should have thrown", false);
  } catch (e) {
    log(`mn_random(100) correctly rejected: ${e}`, true);
  }

  // ── Test 3: mn_encode on a known key (default / explicit "english") ──────
  const hexKey =
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
  let phrase;
  try {
    phrase = mn_encode(hexKey, "english");
    const wordCount = phrase.trim().split(/\s+/).length;
    const ok = wordCount === 25;
    log(
      "mn_encode(english) → " +
        wordCount +
        " words: " +
        (ok ? "PASS" : "FAIL") +
        " — " +
        phrase,
      ok,
    );
  } catch (e) {
    log(`mn_encode(english) failed: ${e}`, false);
    return;
  }

  // ── Test 4: mn_decode round-trip ─────────────────────────────────────────
  try {
    const recovered = mn_decode(phrase, "english");
    const ok = recovered === hexKey;
    log(`mn_decode(english) round-trip: ${ok ? "PASS" : "FAIL"}`, ok);
  } catch (e) {
    log(`mn_decode(english) failed: ${e}`, false);
  }

  // ── Test 5: default language (empty string) behaves as english ───────────
  try {
    const phraseDefault = mn_encode(hexKey, "");
    const recoveredDefault = mn_decode(phraseDefault, "");
    const ok = recoveredDefault === hexKey;
    log(
      "mn_encode/decode with empty language (→ english default): " +
        (ok ? "PASS" : "FAIL"),
      ok,
    );
  } catch (e) {
    log(`default language fallback failed: ${e}`, false);
  }

  // ── Test 6: bad word count rejected ──────────────────────────────────────
  try {
    mn_decode("abbey abbey", "english");
    log("bad word count should have thrown", false);
  } catch (e) {
    log(`bad word count correctly rejected: ${e}`, true);
  }

  // ── Test 7: bad checksum rejected ────────────────────────────────────────
  const words = phrase.split(" ");
  words[24] = "abbey";
  try {
    mn_decode(words.join(" "), "english");
    log("bad checksum should have thrown", false);
  } catch (e) {
    log(`bad checksum correctly rejected: ${e}`, true);
  }

  // ── Test 8: all-zero key round-trip ──────────────────────────────────────
  try {
    const zeroHex = "0".repeat(64);
    const zeroPhrase = mn_encode(zeroHex, "english");
    const zeroRecovered = mn_decode(zeroPhrase, "english");
    const ok = zeroRecovered === zeroHex;
    log(`all-zero key round-trip: ${ok ? "PASS" : "FAIL"}`, ok);
  } catch (e) {
    log(`all-zero key test failed: ${e}`, false);
  }

  // ── Test 9: unknown language rejected ────────────────────────────────────
  try {
    mn_encode(hexKey, "klingon");
    log("unknown language should have thrown", false);
  } catch (e) {
    log(`unknown language correctly rejected: ${e}`, true);
  }

  // ── Test 10: all language round-trips ────────────────────────────────────
  for (const { name, expectedWords } of LANGUAGES) {
    try {
      const p = mn_encode(hexKey, name);
      const recovered = mn_decode(p, name);
      const wordCount = p.trim().split(/\s+/).length;
      const ok = recovered === hexKey && wordCount === expectedWords;
      log(
        `${name} round-trip (${wordCount} words): ${ok ? "PASS" : "FAIL"}`,
        ok,
      );
    } catch (e) {
      log(`${name} round-trip failed: ${e}`, false);
    }
  }
}
