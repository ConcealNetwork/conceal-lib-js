import { bintohex, cn_fast_hash, hextobin } from "../src/js/cnutils.js";
import {
  buildReceiveOutputChecks,
  extractTxPublicKey,
  getTransactionPrefixHash,
  ownsTx,
  ownsTxBatch,
  scanReceiveOutputs,
  scanSpendInputs,
  serializeTransaction,
  serializeTransactionWithHash,
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
 * Hex cursor for manually walking serialized bytes back to fields.
 * Mirrors the CryptoNote varint encoding so the test independently re-derives
 * each value rather than trusting the serializer's own helpers.
 *
 * @param {string} hex
 */
function makeHexReader(hex) {
  let pos = 0; // byte offset
  return {
    /** Decode a LEB128 varint. @returns {number} */
    readVarint() {
      let result = 0;
      let shift = 0;
      for (;;) {
        if (pos * 2 >= hex.length) throw new Error("readVarint: ran past end of buffer");
        const byte = Number.parseInt(hex.slice(pos * 2, pos * 2 + 2), 16);
        pos += 1;
        result += (byte & 0x7f) * 2 ** shift;
        if ((byte & 0x80) === 0) break;
        shift += 7;
      }
      return result;
    },
    /** Read `n` raw bytes as hex. @param {number} n @returns {string} */
    readHex(n) {
      if ((pos + n) * 2 > hex.length) throw new Error(`readHex: need ${n} bytes past end of buffer`);
      const out = hex.slice(pos * 2, pos * 2 + n * 2);
      pos += n;
      return out;
    },
    /** @returns {number} bytes consumed so far */
    bytesRead() {
      return pos;
    },
    /** @returns {number} bytes remaining */
    bytesLeft() {
      return hex.length / 2 - pos;
    },
  };
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

  // ── serializeTransaction: round-trip walk of header-only framing ──────────
  // Build a representative non-RingCT spend tx, serialize the header, then
  // independently decode each varint / fixed-width field and assert every
  // value round-trips. This proves the framing is byte-exact end to end.
  const kImage =
    "1111111111111111111111111111111111111111111111111111111111111111";
  const outKey =
    "2222222222222222222222222222222222222222222222222222222222222222";
  const repTx = {
    version: 1,
    unlock_time: 0,
    vin: [
      {
        type: "input_to_key",
        amount: 1000,
        key_offsets: [42, 7],
        k_image: kImage,
      },
    ],
    vout: [
      {
        amount: 1000,
        target: { type: "txout_to_key", data: { key: outKey } },
      },
    ],
    extra: "0102abcd", // small valid hex
    signatures: [
      [
        "aa".repeat(64), // 64-byte sig hex × 2 (key_offsets.length === 2)
        "bb".repeat(64),
      ],
    ],
  };

  try {
    const headerHex = serializeTransaction(repTx, true);
    const r = makeHexReader(headerHex);

    const version = r.readVarint();
    const unlockTime = r.readVarint();
    const vinCount = r.readVarint();

    // vin[0]: type tag "02", amount, key_offsets length + entries, k_image
    const vinTag = r.readHex(1);
    const vinAmount = r.readVarint();
    const koLen = r.readVarint();
    const ko0 = r.readVarint();
    const ko1 = r.readVarint();
    const readKImage = r.readHex(32);

    const voutCount = r.readVarint();
    const voutAmount = r.readVarint();
    const voutTag = r.readHex(1);
    const readKey = r.readHex(32);

    const extraLen = r.readVarint();
    const readExtra = r.readHex(extraLen);

    const ok =
      version === 1 &&
      unlockTime === 0 &&
      vinCount === 1 &&
      vinTag === "02" &&
      vinAmount === 1000 &&
      koLen === 2 &&
      ko0 === 42 &&
      ko1 === 7 &&
      readKImage === kImage &&
      voutCount === 1 &&
      voutAmount === 1000 &&
      voutTag === "02" &&
      readKey === outKey &&
      extraLen === repTx.extra.length / 2 &&
      readExtra === repTx.extra &&
      r.bytesLeft() === 0; // header ends exactly here — no trailing signatures
    log(
      "serializeTransaction header round-trip walk: " + (ok ? "PASS" : "FAIL"),
      ok,
    );
  } catch (e) {
    log("serializeTransaction round-trip failed: " + e, false);
  }

  // ── getTransactionPrefixHash === cn_fast_hash(headerOnly bytes) ────────────
  try {
    const headerHex = serializeTransaction(repTx, true);
    const expected = cn_fast_hash(headerHex);
    const actual = getTransactionPrefixHash(repTx);
    const ok = actual === expected && /^[0-9a-f]{64}$/.test(actual);
    log("getTransactionPrefixHash matches cn_fast_hash: " + (ok ? "PASS" : "FAIL"), ok);
  } catch (e) {
    log("getTransactionPrefixHash failed: " + e, false);
  }

  // ── full serialization appends signatures after the prefix ─────────────────
  try {
    const headerHex = serializeTransaction(repTx, true);
    const fullHex = serializeTransaction(repTx, false);
    const sigHex = repTx.signatures[0].join("");
    const ok =
      fullHex.startsWith(headerHex) &&
      fullHex.endsWith(sigHex) &&
      fullHex.length === headerHex.length + sigHex.length;
    log("serializeTransaction full appends signatures: " + (ok ? "PASS" : "FAIL"), ok);

    // serializeTransactionWithHash mirrors raw + cn_fast_hash(raw)
    const withHash = serializeTransactionWithHash(repTx);
    const hashOk =
      withHash.raw === fullHex && withHash.hash === cn_fast_hash(fullHex);
    log(
      "serializeTransactionWithHash raw+hash: " + (hashOk ? "PASS" : "FAIL"),
      hashOk,
    );
  } catch (e) {
    log("serializeTransaction signatures failed: " + e, false);
  }

  // ── valid_hex guard throws on bad extra ────────────────────────────────────
  try {
    const badTx = { ...repTx, extra: "zzzz" };
    let threw = false;
    try {
      serializeTransaction(badTx, true);
    } catch {
      threw = true;
    }
    log("serializeTransaction rejects bad extra hex: " + (threw ? "PASS" : "FAIL"), threw);
  } catch (e) {
    log("serializeTransaction bad-extra guard failed: " + e, false);
  }

  // ── agy review: even-length extra + deposit commits to exactly 1 signature ──
  try {
    const threw = (tx) => {
      try {
        serializeTransaction(tx, false);
        return false;
      } catch {
        return true;
      }
    };
    const oddThrew = threw({ ...repTx, extra: "123" }); // odd-length hex
    const undefThrew = threw({ ...repTx, extra: undefined }); // not a string
    const depKey = "33".repeat(32);
    const depMismatch = {
      version: 1,
      unlock_time: 0,
      vin: [{ type: "input_to_deposit_key", amount: 5, outputIndex: 1, term: 21900 }],
      vout: [{ amount: 5, target: { type: "txout_to_deposit_key", data: { keys: [depKey], term: 21900 } } }],
      extra: "00",
      signatures: [["cc".repeat(64), "dd".repeat(64)]], // 2 sigs — prefix commits to 1
    };
    const depThrew = threw(depMismatch);
    const ok = oddThrew && undefThrew && depThrew;
    log(`serializeTransaction guards (even-extra + deposit 1-sig): ${ok ? "PASS" : "FAIL"}`, ok);
  } catch (e) {
    log("serializeTransaction guard tests failed: " + e, false);
  }

  // ── deposit path (txout_to_deposit_key / input_to_deposit_key) ─────────────
  try {
    const depositKey =
      "3333333333333333333333333333333333333333333333333333333333333333";
    const depositTx = {
      version: 1,
      unlock_time: 0,
      vin: [
        {
          type: "input_to_deposit_key",
          amount: 5000,
          outputIndex: 9,
          term: 21900,
          signatures: 1,
        },
      ],
      vout: [
        {
          amount: 5000,
          target: {
            type: "txout_to_deposit_key",
            data: { keys: [depositKey], term: 21900 },
          },
        },
      ],
      extra: "00",
      signatures: [["cc".repeat(64)]],
    };

    const headerHex = serializeTransaction(depositTx, true);
    const r = makeHexReader(headerHex);

    const version = r.readVarint();
    const unlockTime = r.readVarint();
    const vinCount = r.readVarint();
    const vinTag = r.readHex(1); // "03"
    const vinAmount = r.readVarint();
    const vinSigReq = r.readVarint(); // always 1
    const vinOutIdx = r.readVarint();
    const vinTerm = r.readVarint();

    const voutCount = r.readVarint();
    const voutAmount = r.readVarint();
    const voutTag = r.readHex(1); // "03"
    const keysLen = r.readVarint();
    const readDepositKey = r.readHex(32);
    const reqSigCount = r.readVarint(); // always 1
    const voutTerm = r.readVarint(); // encode_varint_term(21900)

    const headerOk =
      version === 1 &&
      unlockTime === 0 &&
      vinCount === 1 &&
      vinTag === "03" &&
      vinAmount === 5000 &&
      vinSigReq === 1 &&
      vinOutIdx === 9 &&
      vinTerm === 21900 &&
      voutCount === 1 &&
      voutAmount === 5000 &&
      voutTag === "03" &&
      keysLen === 1 &&
      readDepositKey === depositKey &&
      reqSigCount === 1 &&
      voutTerm === 21900;
    log("serializeTransaction deposit header walk: " + (headerOk ? "PASS" : "FAIL"), headerOk);

    const fullHex = serializeTransaction(depositTx, false);
    const fullOk =
      fullHex.startsWith(headerHex) &&
      fullHex.endsWith(depositTx.signatures[0].join(""));
    log("serializeTransaction deposit full appends sig: " + (fullOk ? "PASS" : "FAIL"), fullOk);
  } catch (e) {
    log("serializeTransaction deposit path failed: " + e, false);
  }
}
