import { secretbox } from "../src/js/tiers/secretbox.js";

/** @param {Uint8Array} bytes */
function bytesToHex(bytes) {
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/** Wallet `WalletRepository` password → 32-byte key normalization. */
function walletPasswordKey(password) {
  if (password.length > 32) {
    password = password.slice(0, 32);
  }
  if (password.length < 32) {
    password = ("00000000000000000000000000000000" + password).slice(-32);
  }
  let key = new TextEncoder().encode(password);
  if (key.length > 32) {
    key = key.slice(-32);
  }
  return key;
}

/**
 * @param {(msg: string, ok: boolean) => void} log
 */
export async function runSecretboxTests(log) {
  const msg = new TextEncoder().encode("hello wallet");
  const key = new Uint8Array(32);
  const nonce = new Uint8Array(24);
  key.fill(1);
  nonce.fill(2);

  // ── Constants ─────────────────────────────────────────────────────────────
  const constantsOk =
    secretbox.keyLength === 32 &&
    secretbox.nonceLength === 24 &&
    secretbox.overheadLength === 16 &&
    typeof secretbox.open === "function";
  log(
    "keyLength/nonceLength/overheadLength/open: " +
      (constantsOk ? "PASS" : "FAIL"),
    constantsOk,
  );

  // ── Round-trip ────────────────────────────────────────────────────────────
  try {
    const box = secretbox(msg, nonce, key);
    const plain = secretbox.open(box, nonce, key);
    const ok =
      plain !== null &&
      plain.length === msg.length &&
      new TextDecoder().decode(plain) === "hello wallet";
    log(`round-trip encrypt/decrypt: ${ok ? "PASS" : "FAIL"}`, ok);
  } catch (e) {
    log(`round-trip failed: ${e}`, false);
  }

  // ── nacl-fast parity vector (conceal-web-wallet) ──────────────────────────
  try {
    const box = secretbox(msg, nonce, key);
    const expected = "211bcc78c82740f0d531328b233947ce9500b291111aa52c0c11d28a";
    const ok = bytesToHex(box) === expected;
    log(`nacl-fast parity ciphertext: ${ok ? "PASS" : "FAIL"}`, ok);
  } catch (e) {
    log(`parity vector failed: ${e}`, false);
  }

  // ── Wrong key → null ──────────────────────────────────────────────────────
  try {
    const box = secretbox(msg, nonce, key);
    const wrongKey = new Uint8Array(32);
    const result = secretbox.open(box, nonce, wrongKey);
    log(
      "wrong key returns null: " + (result === null ? "PASS" : "FAIL"),
      result === null,
    );
  } catch (e) {
    log(`wrong key test failed: ${e}`, false);
  }

  // ── Tampered box → null ───────────────────────────────────────────────────
  try {
    const box = secretbox(msg, nonce, key);
    const tampered = new Uint8Array(box);
    tampered[0] ^= 0xff;
    const result = secretbox.open(tampered, nonce, key);
    log(
      "tampered box returns null: " + (result === null ? "PASS" : "FAIL"),
      result === null,
    );
  } catch (e) {
    log(`tampered box test failed: ${e}`, false);
  }

  // ── Bad key size ──────────────────────────────────────────────────────────
  try {
    secretbox(msg, nonce, new Uint8Array(16));
    log("bad key size should throw", false);
  } catch (e) {
    log(`bad key size throws: ${e.message}`, e.message === "bad key size");
  }

  // ── Bad nonce size ────────────────────────────────────────────────────────
  try {
    secretbox(msg, new Uint8Array(12), key);
    log("bad nonce size should throw", false);
  } catch (e) {
    log(`bad nonce size throws: ${e.message}`, e.message === "bad nonce size");
  }

  // ── Wallet password padding round-trip ────────────────────────────────────
  try {
    const walletMsg = new TextEncoder().encode('{"keys":{}}');
    const walletKey = walletPasswordKey("пароль");
    const walletNonce = new TextEncoder().encode("012345678901234567890123");
    const encrypted = secretbox(walletMsg, walletNonce, walletKey);
    const decrypted = secretbox.open(encrypted, walletNonce, walletKey);
    const ok =
      decrypted !== null &&
      new TextDecoder().decode(decrypted) === '{"keys":{}}';
    log(`wallet password padding round-trip: ${ok ? "PASS" : "FAIL"}`, ok);
  } catch (e) {
    log(`wallet padding test failed: ${e}`, false);
  }

  // ── Empty message ─────────────────────────────────────────────────────────
  try {
    const empty = new Uint8Array(0);
    const box = secretbox(empty, nonce, key);
    const plain = secretbox.open(box, nonce, key);
    const ok = plain !== null && plain.length === 0;
    log(`empty message round-trip: ${ok ? "PASS" : "FAIL"}`, ok);
  } catch (e) {
    log(`empty message test failed: ${e}`, false);
  }
}
