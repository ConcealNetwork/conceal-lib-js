/**
 * Transaction scan helpers — `ownsTx` workflow for wallet sync.
 *
 * Receive path: `scan_receive_outputs` per tx, or `scan_receive_outputs_batch` for `ownsTxBatch`.
 * Spend path: JS lookups on precomputed wallet context.
 *
 * @module transactions
 */

import { scan_receive_outputs, scan_receive_outputs_batch } from "#crypto-wasm";
import {
  bintohex,
  cn_fast_hash,
  encode_varint,
  encode_varint_term,
  hextobin,
  valid_hex,
} from "./cnutils.js";

export const TX_EXTRA_TAG_PADDING = 0x00;
export const TX_EXTRA_TAG_PUBKEY = 0x01;
export const TX_EXTRA_NONCE = 0x02;
export const TX_EXTRA_MERGE_MINING_TAG = 0x03;
export const TX_EXTRA_MESSAGE_TAG = 0x04;
export const TX_EXTRA_MYSTERIOUS_MINERGATE_TAG = 0xde;
export const TX_EXTRA_TTL = 0x05;

/**
 * @typedef {Object} TxExtra
 * @property {number} type - Extra field tag byte.
 * @property {number[]} data - Payload bytes.
 */

/**
 * @typedef {Object} TxVout
 * @property {string} type - Output target type (`"02"` = key, `"03"` = tagged keys).
 * @property {string} [key] - On-chain output public key (type `"02"`).
 * @property {string[]} [keys] - On-chain keys (type `"03"`).
 */

/**
 * @typedef {Object} TxVin
 * @property {string} [k_image] - Key image hex (spend detection).
 * @property {number[]} [key_offsets] - Relative ring offsets (view-only spend detection).
 */

/**
 * @typedef {Object} TxScanInput
 * @property {string} extraHex - Transaction `extra` field as hex.
 * @property {TxVout[]} vouts - Outputs to scan for incoming funds.
 * @property {TxVin[]} [vins] - Inputs for spend / view-only detection.
 */

/**
 * @typedef {Object} TxScanContext
 * @property {string} viewSecretHex - 64-char hex view secret key.
 * @property {string} spendPublicHex - 64-char hex spend public key.
 * @property {string} [spendSecretHex] - Spend secret when wallet can sign; enables key-image path.
 * @property {string[]} [ownedKeyImages] - Key images known to belong to this wallet (spend path).
 * @property {number[]} [knownGlobalOutputIndexes] - Global output indexes owned (view-only path).
 */

/**
 * @typedef {Object} ReceiveOutputChecks
 * @property {number[]} indices - Derivation indices for `derive_public_key`.
 * @property {string[]} keys - On-chain output public keys (64-char hex).
 */

/**
 * Parse transaction extra bytes into tagged chunks (CryptoNote tx_extra).
 *
 * @param {number[] | Uint8Array} oExtra - Raw extra field bytes.
 * @returns {TxExtra[]}
 */
export function parseTxExtra(oExtra) {
  const extra = Array.from(oExtra);
  /** @type {TxExtra[]} */
  const extras = [];
  let hasFoundPubKey = false;

  while (extra.length > 0) {
    try {
      let extraSize = 0;
      let startOffset = 0;

      if (
        extra[0] === TX_EXTRA_NONCE ||
        extra[0] === TX_EXTRA_MERGE_MINING_TAG ||
        extra[0] === TX_EXTRA_MYSTERIOUS_MINERGATE_TAG
      ) {
        extraSize = extra[1];
        startOffset = 2;
      } else if (extra[0] === TX_EXTRA_TAG_PUBKEY) {
        extraSize = 32;
        startOffset = 1;
        hasFoundPubKey = true;
      } else if (extra[0] === TX_EXTRA_MESSAGE_TAG) {
        extraSize = extra[1];
        startOffset = 2;
      } else if (extra[0] === TX_EXTRA_TTL) {
        extraSize = extra[1];
        startOffset = 2;
      } else if (extra[0] === TX_EXTRA_TAG_PADDING) {
        // padding — no payload
      }

      if (extraSize === 0) {
        if (!hasFoundPubKey) {
          throw new Error(`Invalid extra size ${extra[0]}`);
        }
        break;
      }

      if (startOffset > 0 && extraSize > 0) {
        const data = extra.slice(startOffset, startOffset + extraSize);
        extras.push({ type: extra[0], data });
        extra.splice(0, startOffset + extraSize);
      } else if (!extraSize) {
        break;
      }
    } catch {
      break;
    }
  }

  return extras;
}

/**
 * Extract the transaction public key from `extra` hex (first `TX_EXTRA_TAG_PUBKEY`).
 *
 * @param {string} extraHex - Transaction extra field as hex.
 * @returns {string | null} 64-char hex tx public key, or `null` if missing.
 */
export function extractTxPublicKey(extraHex) {
  const uint8Array = hextobin(extraHex);
  const extras = parseTxExtra(uint8Array);

  for (const extra of extras) {
    if (extra.type === TX_EXTRA_TAG_PUBKEY && extra.data.length === 32) {
      let raw = "";
      for (let i = 0; i < 32; ++i) {
        raw += String.fromCharCode(extra.data[i]);
      }
      return bintohex(raw);
    }
  }

  return null;
}

/**
 * Build flat derivation-index / on-chain-key lists for receive scanning.
 * Matches `TransactionsExplorer.ownsTx` vout index rules (type `"02"` vs `"03"`).
 *
 * @param {TxVout[]} vouts
 * @returns {ReceiveOutputChecks}
 */
export function buildReceiveOutputChecks(vouts) {
  /** @type {number[]} */
  const indices = [];
  /** @type {string[]} */
  const keys = [];
  let keyIndex = 0;

  for (let iOut = 0; iOut < vouts.length; iOut++) {
    const out = vouts[iOut];
    if (out.type === "02" && typeof out.key === "string") {
      indices.push(keyIndex);
      keys.push(out.key);
      keyIndex += 1;
    } else if (out.type === "03" && Array.isArray(out.keys)) {
      for (let iKey = 0; iKey < out.keys.length; iKey++) {
        indices.push(iOut);
        keys.push(out.keys[iKey]);
        keyIndex += 1;
      }
    }
  }

  return { indices, keys };
}

/**
 * Flat arrays for `scan_receive_outputs_batch` (one WASM call for many txs).
 *
 * @param {TxScanInput[]} txs
 * @returns {{ txPubHex: string[], indices: Uint32Array, keys: string[], txOffsets: Uint32Array }}
 */
function buildBatchReceivePayload(txs) {
  /** @type {string[]} */
  const txPubHex = [];
  /** @type {number[]} */
  const indices = [];
  /** @type {string[]} */
  const keys = [];
  /** @type {number[]} */
  const txOffsets = [0];

  for (const tx of txs) {
    const pub = extractTxPublicKey(tx.extraHex);
    txPubHex.push(pub ?? "");
    const checks = buildReceiveOutputChecks(tx.vouts);
    indices.push(...checks.indices);
    keys.push(...checks.keys);
    txOffsets.push(indices.length);
  }

  return {
    txPubHex,
    indices: Uint32Array.from(indices),
    keys,
    txOffsets: Uint32Array.from(txOffsets),
  };
}

/**
 * Scan vouts for an incoming transfer (single WASM call).
 *
 * @param {string} txPubHex - 64-char hex transaction public key.
 * @param {string} viewSecHex - 64-char hex view secret key.
 * @param {string} spendPubHex - 64-char hex spend public key.
 * @param {TxVout[]} vouts
 * @returns {boolean}
 */
export function scanReceiveOutputs(txPubHex, viewSecHex, spendPubHex, vouts) {
  const { indices, keys } = buildReceiveOutputChecks(vouts);
  if (indices.length === 0) {
    return false;
  }
  return scan_receive_outputs(txPubHex, viewSecHex, spendPubHex, indices, keys);
}

/**
 * Scan vins for spend ownership (JS-only; wallet supplies context sets).
 *
 * @param {TxVin[]} vins
 * @param {TxScanContext} ctx
 * @returns {boolean}
 */
export function scanSpendInputs(vins, ctx) {
  if (!Array.isArray(vins) || vins.length === 0) {
    return false;
  }

  const spendSecret = ctx.spendSecretHex;
  const hasSpend =
    typeof spendSecret === "string" &&
    spendSecret !== null &&
    spendSecret !== "";

  if (hasSpend) {
    const owned = ctx.ownedKeyImages;
    if (!Array.isArray(owned) || owned.length === 0) {
      return false;
    }
    const ownedSet = new Set(owned);
    for (const vin of vins) {
      if (vin.k_image && ownedSet.has(vin.k_image)) {
        return true;
      }
    }
    return false;
  }

  const knownIndexes = ctx.knownGlobalOutputIndexes;
  if (!Array.isArray(knownIndexes) || knownIndexes.length === 0) {
    return false;
  }
  const indexSet = new Set(knownIndexes);

  for (const vin of vins) {
    if (!Array.isArray(vin.key_offsets) || vin.key_offsets.length === 0) {
      continue;
    }
    const absoluteOffsets = vin.key_offsets.slice();
    for (let i = 1; i < absoluteOffsets.length; ++i) {
      absoluteOffsets[i] += absoluteOffsets[i - 1];
    }
    for (const index of absoluteOffsets) {
      if (indexSet.has(index)) {
        return true;
      }
    }
  }

  return false;
}

/**
 * Returns whether the wallet owns this transaction (receive or spend).
 *
 * @param {TxScanInput} tx
 * @param {TxScanContext} ctx
 * @returns {boolean}
 */
export function ownsTx(tx, ctx) {
  const txPub = extractTxPublicKey(tx.extraHex);
  if (txPub) {
    try {
      if (
        scanReceiveOutputs(
          txPub,
          ctx.viewSecretHex,
          ctx.spendPublicHex,
          tx.vouts,
        )
      ) {
        return true;
      }
    } catch {
      return false;
    }
  }

  if (Array.isArray(tx.vins) && tx.vins.length > 0) {
    return scanSpendInputs(tx.vins, ctx);
  }

  return false;
}

/**
 * Batch `ownsTx` — one WASM receive scan for the whole array, then spend checks in JS.
 *
 * @param {TxScanInput[]} txs
 * @param {TxScanContext} ctx
 * @returns {boolean[]}
 */
export function ownsTxBatch(txs, ctx) {
  if (!Array.isArray(txs) || txs.length === 0) {
    return [];
  }

  const { txPubHex, indices, keys, txOffsets } = buildBatchReceivePayload(txs);

  /** @type {boolean[]} */
  let receiveOwned;
  try {
    const flags = scan_receive_outputs_batch(
      ctx.viewSecretHex,
      ctx.spendPublicHex,
      txPubHex,
      indices,
      keys,
      txOffsets,
    );
    receiveOwned = flags.map((f) => f !== 0);
  } catch {
    return txs.map(() => false);
  }

  if (receiveOwned.length !== txs.length) {
    return txs.map(() => false);
  }

  /** @type {boolean[]} */
  const results = new Array(txs.length);
  for (let i = 0; i < txs.length; i++) {
    if (receiveOwned[i]) {
      results[i] = true;
      continue;
    }
    const vins = txs[i].vins;
    if (Array.isArray(vins) && vins.length > 0) {
      results[i] = scanSpendInputs(vins, ctx);
    } else {
      results[i] = false;
    }
  }
  return results;
}

/**
 * @typedef {Object} TxSerializeVinTarget
 * @property {string} type - Input type (`"input_to_key"` or `"input_to_deposit_key"`).
 * @property {number | string} [amount] - Input amount (uint64; pass large values as strings).
 * @property {number[]} [key_offsets] - Relative ring offsets (`input_to_key`).
 * @property {string} [k_image] - 64-char hex key image (`input_to_key`).
 * @property {number | string} [outputIndex] - Deposit output index (`input_to_deposit_key`).
 * @property {number | string} [term] - Deposit term in blocks (`input_to_deposit_key`).
 * @property {number} [signatures] - Expected signature count for `input_to_deposit_key`.
 */

/**
 * @typedef {Object} TxSerializeVoutTargetData
 * @property {string} [key] - 64-char hex output public key (`txout_to_key`).
 * @property {string[]} [keys] - 64-char hex output keys (`txout_to_deposit_key`).
 * @property {number | string} [term] - Deposit term in blocks (`txout_to_deposit_key`).
 */

/**
 * @typedef {Object} TxSerializeVoutTarget
 * @property {string} type - Target type (`"txout_to_key"` or `"txout_to_deposit_key"`).
 * @property {TxSerializeVoutTargetData} data - Target payload.
 */

/**
 * @typedef {Object} TxSerializeVout
 * @property {number | string} amount - Output amount (uint64; pass large values as strings).
 * @property {TxSerializeVoutTarget} target - Output target.
 */

/**
 * @typedef {Object} TxToSerialize
 * @property {number | string} version - Transaction version (uint64).
 * @property {number | string} unlock_time - Unlock time / block height (uint64).
 * @property {TxSerializeVinTarget[]} vin - Transaction inputs.
 * @property {TxSerializeVout[]} vout - Transaction outputs.
 * @property {string} extra - `extra` field as an even-length hex string.
 * @property {string[][]} signatures - Per-input ring signatures (omitted when serializing header only).
 */

/**
 * @typedef {Object} TxSerializeWithHash
 * @property {string} raw - Full serialized transaction hex (prefix + signatures).
 * @property {string} hash - `cn_fast_hash` of the full serialized transaction.
 */

/**
 * Serialize a CryptoNote transaction to broadcast-ready hex (non-RingCT / plain
 * ring-signature path only). Ported byte-for-byte from `CnTransactions.serialize_tx`
 * in conceal-web-wallet's `Cn.ts`.
 *
 * @param {TxToSerialize} tx - Transaction to serialize.
 * @param {boolean} [headerOnly] - When `true`, emit only the prefix (no signatures).
 * @returns {string} Serialized transaction hex.
 */
export function serializeTransaction(tx, headerOnly = false) {
  let buf = "";
  buf += encode_varint(tx.version);
  buf += encode_varint(tx.unlock_time);
  buf += encode_varint(tx.vin.length);

  for (let i = 0; i < tx.vin.length; i++) {
    const vin = tx.vin[i];
    switch (vin.type) {
      case "input_to_key": {
        buf += "02";
        buf += encode_varint(vin.amount);
        const keyOffsets = vin.key_offsets || [];
        buf += encode_varint(keyOffsets.length);
        for (let j = 0; j < keyOffsets.length; j++) {
          buf += encode_varint(keyOffsets[j]);
        }
        if (typeof vin.k_image !== "string" || vin.k_image.length !== 64) {
          throw new Error("input_to_key requires a 64-char k_image hex");
        }
        buf += vin.k_image;
        break;
      }
      case "input_to_deposit_key": {
        buf += "03";
        buf += encode_varint(vin.amount);
        buf += encode_varint(1); // always 1 for deposits/withdrawals
        buf += encode_varint(vin.outputIndex || 0);
        buf += encode_varint(vin.term || 0);
        break;
      }
      default:
        throw new Error(`Unhandled vin type: ${vin.type}`);
    }
  }

  buf += encode_varint(tx.vout.length);
  for (let i = 0; i < tx.vout.length; i++) {
    const vout = tx.vout[i];
    buf += encode_varint(vout.amount);
    switch (vout.target.type) {
      case "txout_to_key": {
        buf += "02";
        if (
          typeof vout.target.data.key !== "string" ||
          vout.target.data.key.length !== 64
        ) {
          throw new Error("txout_to_key requires a 64-char key hex");
        }
        buf += vout.target.data.key;
        break;
      }
      case "txout_to_deposit_key": {
        buf += "03";
        const keys = vout.target.data.keys || [];
        buf += encode_varint(keys.length); // varint for number of keys, only one for deposit
        for (let j = 0; j < keys.length; j++) {
          if (typeof keys[j] !== "string" || keys[j].length !== 64) {
            throw new Error("txout_to_deposit_key requires 64-char key hex");
          }
          buf += keys[j];
        }
        buf += encode_varint(1); // requiredSignatureCount is always 1 for deposits
        buf += encode_varint_term(vout.target.data.term || 0); // term in blocks
        break;
      }
      default:
        throw new Error(`Unhandled txout target type: ${vout.target.type}`);
    }
  }

  // Must be an EVEN-length hex string: valid_hex only checks the alphabet, so an
  // odd-length extra would make `extra.length / 2` fractional and silently
  // corrupt the byte count + append a half-byte. Also guards against undefined.
  if (
    typeof tx.extra !== "string" ||
    !valid_hex(tx.extra) ||
    tx.extra.length % 2 !== 0
  ) {
    throw new Error("Tx extra must be an even-length hex string");
  }

  buf += encode_varint(tx.extra.length / 2); // extra is stored as a hex string
  buf += tx.extra;

  if (!headerOnly) {
    if (tx.vin.length !== tx.signatures.length) {
      throw new Error("Signatures length != vin length");
    }
    for (let i = 0; i < tx.vin.length; i++) {
      const vin = tx.vin[i];
      let expectedSignatures;
      if (vin.type === "input_to_deposit_key") {
        // The prefix commits to exactly 1 required signature (encode_varint(1)),
        // so the appended signature count must be 1 — don't trust vin.signatures.
        expectedSignatures = 1;
      } else if (vin.type === "input_to_key") {
        expectedSignatures = (vin.key_offsets || []).length;
      } else {
        expectedSignatures = 0;
      }
      if (tx.signatures[i].length !== expectedSignatures) {
        throw new Error(
          `Unexpected signature count for input ${i}: expected ${expectedSignatures}, got ${tx.signatures[i].length}`,
        );
      }
      for (let j = 0; j < tx.signatures[i].length; j++) {
        buf += tx.signatures[i][j];
      }
    }
  }

  return buf;
}

/**
 * Compute the transaction prefix hash (`cn_fast_hash` of the header-only serialization).
 * Ported from `CnTransactions.get_tx_prefix_hash`.
 *
 * @param {TxToSerialize} tx - Transaction to hash.
 * @returns {string} 64-char hex prefix hash.
 */
export function getTransactionPrefixHash(tx) {
  const prefix = serializeTransaction(tx, true);
  return cn_fast_hash(prefix);
}

/**
 * Serialize a transaction and compute its full hash.
 * Ported from `CnTransactions.serialize_tx_with_hash`.
 *
 * @param {TxToSerialize} tx - Transaction to serialize.
 * @returns {TxSerializeWithHash}
 */
export function serializeTransactionWithHash(tx) {
  const raw = serializeTransaction(tx, false);
  return {
    raw,
    hash: cn_fast_hash(raw),
  };
}
