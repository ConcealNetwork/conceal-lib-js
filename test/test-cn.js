import * as cn from "../src/js/cn.js";
import * as random from "../src/js/random.js";
import {
  cn_fast_hash,
  derive_public_key,
  generate_key_derivation,
  generate_keys,
  sc_check,
  sc_reduce32,
} from "./wasm/crypto/crypto.js";

const SEED = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

const HEX64 = /^[0-9a-f]{64}$/;

/**
 * @param {(msg: string, ok: boolean) => void} log
 */
export async function runCnTests(log) {
  // ── random.rand32 / rand16 / rand8 ────────────────────────────────────────
  try {
    const r32 = random.rand32();
    const r16 = random.rand16();
    const r8 = random.rand8();
    const ok =
      HEX64.test(r32) &&
      /^[0-9a-f]{32}$/.test(r16) &&
      /^[0-9a-f]{16}$/.test(r8);
    log(
      "rand32/rand16/rand8 hex lengths (64/32/16): " + (ok ? "PASS" : "FAIL"),
      ok,
    );
  } catch (e) {
    log("random helpers failed: " + e, false);
  }

  // ── random.random_scalar ───────────────────────────────────────────────────
  try {
    const scalar = random.random_scalar();
    const ok = HEX64.test(scalar) && sc_check(scalar);
    log(
      "random_scalar → 64-char canonical scalar (sc_check): " +
        (ok ? "PASS" : "FAIL"),
      ok,
    );
  } catch (e) {
    log("random_scalar failed: " + e, false);
  }

  try {
    const seed = random.rand32();
    const reduced = sc_reduce32(seed);
    const ok = HEX64.test(reduced) && sc_check(reduced);
    log("sc_reduce32(rand32) reference shape: " + (ok ? "PASS" : "FAIL"), ok);
  } catch (e) {
    log("sc_reduce32(rand32) reference failed: " + e, false);
  }

  // ── cn.random_keypair ─────────────────────────────────────────────────────
  try {
    const keys = cn.random_keypair();
    const ok =
      keys &&
      typeof keys.sec === "string" &&
      typeof keys.pub === "string" &&
      HEX64.test(keys.sec) &&
      HEX64.test(keys.pub);
    log(
      "random_keypair → {sec, pub} 64-char hex: " + (ok ? "PASS" : "FAIL"),
      ok,
    );
  } catch (e) {
    log("random_keypair failed: " + e, false);
  }

  // ── cn.underive_public_key round-trip with derive_public_key ─────────────
  try {
    const spend = generate_keys(SEED);
    const view = generate_keys(cn_fast_hash(SEED));
    const derivation = generate_key_derivation(view.pub, spend.sec);
    const derivedPub = derive_public_key(derivation, 0, spend.pub);
    const basePub = cn.underive_public_key(derivation, 0, derivedPub);
    const ok = basePub === spend.pub;
    log(
      "underive_public_key ∘ derive_public_key === base pub: " +
        (ok ? "PASS" : "FAIL"),
      ok,
    );
  } catch (e) {
    log("underive_public_key round-trip failed: " + e, false);
  }

  // ── cn.underive_public_key rejects bad lengths ────────────────────────────
  try {
    cn.underive_public_key("ab", 0, "cd");
    log("underive_public_key should reject short inputs", false);
  } catch (e) {
    const ok = e instanceof Error;
    log(
      "underive_public_key rejects invalid length: " + (ok ? "PASS" : "FAIL"),
      ok,
    );
  }
}
