import { bintohex, hextobin } from "../src/js/cnutils.js";
import {
  buildReceiveOutputChecks,
  extractTxPublicKey,
  ownsTx,
  ownsTxBatch,
  scanReceiveOutputs,
  scanSpendInputs,
  TX_EXTRA_TAG_PUBKEY,
} from "../src/js/transactions.js";
import init, {
  derive_public_key,
  generate_key_derivation,
  generate_keys,
} from "./wasm/crypto/crypto.js";

/**
 * @param {string} txPubHex
 * @returns {string}
 */
function extraHexWithTxPub(txPubHex) {
  const pub = hextobin(txPubHex);
  const extra = new Uint8Array(1 + 32);
  extra[0] = TX_EXTRA_TAG_PUBKEY;
  extra.set(pub, 1);
  return bintohex(extra);
}

/**
 * @param {(msg: string, ok: boolean) => void} log
 */
export async function runTransactionsTests(log) {
  await init();

  // 32-byte seeds — must be exactly 64 hex chars (see test-crypto.js)
  const txSeed =
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
  const walletSeed =
    "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f";
  const txKeys = generate_keys(txSeed);
  const walletKeys = generate_keys(walletSeed);

  const derivation = generate_key_derivation(txKeys.pub, walletKeys.sec);
  const derivedKey0 = derive_public_key(derivation, 0, walletKeys.pub);
  const extraHex = extraHexWithTxPub(txKeys.pub);

  // ── extractTxPublicKey ───────────────────────────────────────────────────
  try {
    const extracted = extractTxPublicKey(extraHex);
    const ok = extracted === txKeys.pub;
    log("extractTxPublicKey: " + (ok ? "PASS" : "FAIL"), ok);
  } catch (e) {
    log("extractTxPublicKey failed: " + e, false);
  }

  // ── scanReceiveOutputs type 02 ───────────────────────────────────────────
  try {
    const ok = scanReceiveOutputs(txKeys.pub, walletKeys.sec, walletKeys.pub, [
      { type: "02", key: derivedKey0 },
    ]);
    log("scanReceiveOutputs type 02 match: " + (ok ? "PASS" : "FAIL"), ok);
  } catch (e) {
    log("scanReceiveOutputs type 02 failed: " + e, false);
  }

  // ── scanReceiveOutputs type 03 (vout index, not keyIndex) ────────────────
  try {
    const iOut = 1;
    const derivedAtVout = derive_public_key(derivation, iOut, walletKeys.pub);
    const wrongAt0 = derive_public_key(derivation, 0, walletKeys.pub);
    const checks = buildReceiveOutputChecks([
      { type: "02", key: wrongAt0 },
      { type: "03", keys: [derivedAtVout, wrongAt0] },
    ]);
    const ok =
      checks.indices[0] === 0 &&
      checks.indices[1] === 1 &&
      checks.indices[2] === 1;
    log(
      "buildReceiveOutputChecks type 03 indices: " + (ok ? "PASS" : "FAIL"),
      ok,
    );
    const match = scanReceiveOutputs(
      txKeys.pub,
      walletKeys.sec,
      walletKeys.pub,
      [
        { type: "02", key: wrongAt0 },
        { type: "03", keys: [derivedAtVout] },
      ],
    );
    log(
      "scanReceiveOutputs type 03 match: " + (match ? "PASS" : "FAIL"),
      match,
    );
  } catch (e) {
    log("type 03 scan failed: " + e, false);
  }

  // ── ownsTx receive path ──────────────────────────────────────────────────
  try {
    const ok = ownsTx(
      {
        extraHex,
        vouts: [{ type: "02", key: derivedKey0 }],
      },
      {
        viewSecretHex: walletKeys.sec,
        spendPublicHex: walletKeys.pub,
      },
    );
    log("ownsTx receive match: " + (ok ? "PASS" : "FAIL"), ok);
  } catch (e) {
    log("ownsTx receive failed: " + e, false);
  }

  // ── ownsTx negative (wrong spend pub) ────────────────────────────────────
  try {
    const other = generate_keys(
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    );
    const ok = !ownsTx(
      {
        extraHex,
        vouts: [{ type: "02", key: derivedKey0 }],
      },
      {
        viewSecretHex: walletKeys.sec,
        spendPublicHex: other.pub,
      },
    );
    log("ownsTx wrong spend pub: " + (ok ? "PASS" : "FAIL"), ok);
  } catch (e) {
    log("ownsTx negative failed: " + e, false);
  }

  // ── scanSpendInputs key image ────────────────────────────────────────────
  try {
    const ok = scanSpendInputs([{ k_image: "abc123" }], {
      spendSecretHex: walletKeys.sec,
      spendPublicHex: walletKeys.pub,
      viewSecretHex: walletKeys.sec,
      ownedKeyImages: ["abc123", "def456"],
    });
    log("scanSpendInputs key image: " + (ok ? "PASS" : "FAIL"), ok);
  } catch (e) {
    log("scanSpendInputs key image failed: " + e, false);
  }

  // ── scanSpendInputs global indexes (view-only) ─────────────────────────────
  try {
    const ok = scanSpendInputs([{ key_offsets: [2, 3] }], {
      viewSecretHex: walletKeys.sec,
      spendPublicHex: walletKeys.pub,
      knownGlobalOutputIndexes: [5, 10],
    });
    log("scanSpendInputs global index: " + (ok ? "PASS" : "FAIL"), ok);
  } catch (e) {
    log("scanSpendInputs global index failed: " + e, false);
  }

  // ── ownsTxBatch ──────────────────────────────────────────────────────────
  try {
    const ctx = {
      viewSecretHex: walletKeys.sec,
      spendPublicHex: walletKeys.pub,
    };
    const txs = [
      {
        extraHex,
        vouts: [{ type: "02", key: derivedKey0 }],
      },
      {
        extraHex: "00",
        vouts: [],
      },
    ];
    const batch = ownsTxBatch(txs, ctx);
    const ok =
      Array.isArray(batch) &&
      batch.length === 2 &&
      batch[0] === true &&
      batch[1] === false;
    log("ownsTxBatch: " + (ok ? "PASS" : "FAIL"), ok);

    const parity = txs.every((tx, i) => ownsTx(tx, ctx) === batch[i]);
    log(
      "ownsTxBatch parity with ownsTx: " + (parity ? "PASS" : "FAIL"),
      parity,
    );
  } catch (e) {
    log("ownsTxBatch failed: " + e, false);
  }
}
