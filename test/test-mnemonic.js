import init, { mn_random, mn_encode, mn_decode } from "./pkg/mnemonic/mnemonic.js";

/**
 * Run all mnemonic tests.
 * @param {(msg: string, ok: boolean) => void} log - callback provided by the test runner
 */
export async function runMnemonicTests(log) {
  await init();

  // Test 1: mn_random(256) returns a 64-char hex string
  let entropy;
  try {
    entropy = mn_random(256);
    const ok = typeof entropy === "string" && entropy.length === 64 && /^[0-9a-f]+$/.test(entropy);
    log("mn_random(256) → 64-char hex: " + (ok ? "PASS" : "FAIL — got: " + entropy), ok);
  } catch (e) {
    log("mn_random(256) failed: " + e, false);
    return;
  }

  // Test 2: mn_random with invalid bits rejected
  try {
    mn_random(100);
    log("mn_random(100) should have thrown", false);
  } catch (e) {
    log("mn_random(100) correctly rejected: " + e, true);
  }

  // Test 3: mn_encode on a known 64-char hex key
  const hexKey = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
  let phrase;
  try {
    phrase = mn_encode(hexKey);
    const wordCount = phrase.trim().split(/\s+/).length;
    const ok = wordCount === 25;
    log("mn_encode → " + wordCount + " words: " + (ok ? "PASS" : "FAIL") + " — " + phrase, ok);
  } catch (e) {
    log("mn_encode failed: " + e, false);
    return;
  }

  // Test 4: mn_decode round-trip
  try {
    const recovered = mn_decode(phrase);
    const ok = recovered === hexKey;
    log("mn_decode round-trip: " + (ok ? "PASS" : "FAIL"), ok);
  } catch (e) {
    log("mn_decode failed: " + e, false);
  }

  // Test 5: bad word count rejected
  try {
    mn_decode("abbey abbey");
    log("bad word count should have thrown", false);
  } catch (e) {
    log("bad word count correctly rejected: " + e, true);
  }

  // Test 6: bad checksum rejected
  const words = phrase.split(" ");
  words[24] = "abbey";
  try {
    mn_decode(words.join(" "));
    log("bad checksum should have thrown", false);
  } catch (e) {
    log("bad checksum correctly rejected: " + e, true);
  }

  // Test 7: all-zero key round-trip
  try {
    const zeroHex = "0".repeat(64);
    const zeroPhrase = mn_encode(zeroHex);
    const zeroRecovered = mn_decode(zeroPhrase);
    const ok = zeroRecovered === zeroHex;
    log("all-zero key round-trip: " + (ok ? "PASS" : "FAIL"), ok);
  } catch (e) {
    log("all-zero key test failed: " + e, false);
  }
}
