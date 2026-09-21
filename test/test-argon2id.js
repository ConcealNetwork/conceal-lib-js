/**
 * Argon2id KDF tests (RFC 9106 / RustCrypto-compatible known answers).
 *
 * Independent vectors from published PHC encodings (password=`password`,
 * salt=`somesalt`): mudge/argon2id and tarantool/argon2 READMEs — not generated
 * from this implementation.
 */
import init, { argon2id } from "./wasm/crypto/crypto.js";

/** @param {string} s */
function asciiHex(s) {
  return Array.from(new TextEncoder().encode(s), (b) =>
    b.toString(16).padStart(2, "0"),
  ).join("");
}

/**
 * @param {(msg: string, ok: boolean) => void} log
 */
export async function runArgon2idTests(log) {
  await init();

  const pwd = asciiHex("password");
  const salt = asciiHex("somesalt");

  // Known-answer: m=256 KiB, t=2, p=1 (mudge/argon2id PHC string)
  try {
    const got = argon2id(pwd, salt, 256, 2, 1);
    const expected =
      "9dfeb910e80bad0311fee20f9c0e2b12c17987b4cac90c2ef54d5b3021c68bfe";
    const ok = got === expected && got.length === 64;
    log(`argon2id KAT m=256 t=2 p=1: ${ok ? "PASS" : `FAIL got ${got}`}`, ok);
  } catch (e) {
    log(`argon2id KAT failed: ${e}`, false);
  }

  // Known-answer: m=4096 KiB, t=3, p=1 (tarantool/argon2 README)
  try {
    const got = argon2id(pwd, salt, 4096, 3, 1);
    const expected =
      "a8b9a5e5c6ea1403ba63154786b4811cfd1459dc6b23190d70cf1a317ddb9735";
    const ok = got === expected;
    log(`argon2id KAT m=4096 t=3 p=1: ${ok ? "PASS" : `FAIL got ${got}`}`, ok);
  } catch (e) {
    log(`argon2id KAT m=4096 failed: ${e}`, false);
  }

  // Determinism
  try {
    const a = argon2id(pwd, salt, 256, 2, 1);
    const b = argon2id(pwd, salt, 256, 2, 1);
    log(`argon2id deterministic: ${a === b ? "PASS" : "FAIL"}`, a === b);
  } catch (e) {
    log(`argon2id determinism failed: ${e}`, false);
  }

  // Different salts → different outputs
  try {
    const salt2 = asciiHex("othersalt");
    const a = argon2id(pwd, salt, 256, 2, 1);
    const b = argon2id(pwd, salt2, 256, 2, 1);
    log(
      `argon2id different salts differ: ${a !== b ? "PASS" : "FAIL"}`,
      a !== b,
    );
  } catch (e) {
    log(`argon2id salt diversity failed: ${e}`, false);
  }

  // Binary password: 0x00 and non-ASCII UTF-8 (é = c3 a9)
  try {
    const binPwd = `00${asciiHex("café")}`;
    const out = argon2id(binPwd, salt, 256, 2, 1);
    const ok =
      typeof out === "string" &&
      out.length === 64 &&
      out !== argon2id(pwd, salt, 256, 2, 1);
    log(`argon2id binary password (00 + UTF-8): ${ok ? "PASS" : "FAIL"}`, ok);
  } catch (e) {
    log(`argon2id binary password failed: ${e}`, false);
  }

  // Empty password allowed
  try {
    const out = argon2id("", salt, 256, 2, 1);
    log(
      `argon2id empty password: ${out.length === 64 ? "PASS" : "FAIL"}`,
      out.length === 64,
    );
  } catch (e) {
    log(`argon2id empty password failed: ${e}`, false);
  }

  // Malformed hex
  try {
    argon2id("0", salt, 256, 2, 1);
    log("argon2id should reject odd-length hex", false);
  } catch (e) {
    log(`argon2id rejects odd-length hex: ${e}`, true);
  }

  try {
    argon2id("zz", salt, 256, 2, 1);
    log("argon2id should reject non-hex", false);
  } catch (e) {
    log(`argon2id rejects non-hex: ${e}`, true);
  }

  // Invalid salt (< 8 bytes)
  try {
    argon2id(pwd, "00112233445566", 256, 2, 1);
    log("argon2id should reject short salt", false);
  } catch (e) {
    log(`argon2id rejects short salt: ${e}`, true);
  }

  // Invalid salt (> 64 bytes)
  try {
    argon2id(pwd, "aa".repeat(65), 256, 2, 1);
    log("argon2id should reject long salt", false);
  } catch (e) {
    log(`argon2id rejects long salt: ${e}`, true);
  }

  // Invalid memory / time / parallelism
  for (const [label, args, expectFail] of [
    ["memory < 8p", [pwd, salt, 7, 2, 1], true],
    ["memory > 65536", [pwd, salt, 65537, 2, 1], true],
    ["iterations 0", [pwd, salt, 256, 0, 1], true],
    ["iterations > 64", [pwd, salt, 256, 65, 1], true],
    ["parallelism 0", [pwd, salt, 256, 2, 0], true],
    ["parallelism > 4", [pwd, salt, 256, 2, 5], true],
    ["wallet profile 19MiB", [pwd, salt, 19456, 2, 1], false],
  ]) {
    try {
      const out = argon2id(...args);
      if (expectFail) {
        log(`argon2id should reject ${label}`, false);
      } else {
        log(
          `argon2id ${label}: ${out.length === 64 ? "PASS" : "FAIL"}`,
          out.length === 64,
        );
      }
    } catch (e) {
      if (expectFail) {
        log(`argon2id rejects ${label}: ${e}`, true);
      } else {
        log(`argon2id ${label} failed: ${e}`, false);
      }
    }
  }

  // Export smoke: function is present after init (this suite)
  log(
    `argon2id export available: ${typeof argon2id === "function" ? "PASS" : "FAIL"}`,
    typeof argon2id === "function",
  );
}
