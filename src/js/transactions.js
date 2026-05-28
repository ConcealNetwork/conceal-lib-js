/**
 * Transaction scan helpers — `ownsTx` workflow for wallet sync.
 *
 * Receive path: `scan_receive_outputs` per tx, or `scan_receive_outputs_batch` for `ownsTxBatch`.
 * Spend path: JS lookups on precomputed wallet context.
 *
 * @module transactions
 */

import { bintohex, hextobin } from "./cnutils.js";
import {
  scan_receive_outputs,
  scan_receive_outputs_batch,
} from "#crypto-wasm";

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
    typeof spendSecret === "string" && spendSecret !== null && spendSecret !== "";

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
        scanReceiveOutputs(txPub, ctx.viewSecretHex, ctx.spendPublicHex, tx.vouts)
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
