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
export function parseTxExtra(oExtra: number[] | Uint8Array): TxExtra[];
/**
 * Extract the transaction public key from `extra` hex (first `TX_EXTRA_TAG_PUBKEY`).
 *
 * @param {string} extraHex - Transaction extra field as hex.
 * @returns {string | null} 64-char hex tx public key, or `null` if missing.
 */
export function extractTxPublicKey(extraHex: string): string | null;
/**
 * Build flat derivation-index / on-chain-key lists for receive scanning.
 * Matches `TransactionsExplorer.ownsTx` vout index rules (type `"02"` vs `"03"`).
 *
 * @param {TxVout[]} vouts
 * @returns {ReceiveOutputChecks}
 */
export function buildReceiveOutputChecks(vouts: TxVout[]): ReceiveOutputChecks;
/**
 * Scan vouts for an incoming transfer (single WASM call).
 *
 * @param {string} txPubHex - 64-char hex transaction public key.
 * @param {string} viewSecHex - 64-char hex view secret key.
 * @param {string} spendPubHex - 64-char hex spend public key.
 * @param {TxVout[]} vouts
 * @returns {boolean}
 */
export function scanReceiveOutputs(txPubHex: string, viewSecHex: string, spendPubHex: string, vouts: TxVout[]): boolean;
/**
 * Scan vins for spend ownership (JS-only; wallet supplies context sets).
 *
 * @param {TxVin[]} vins
 * @param {TxScanContext} ctx
 * @returns {boolean}
 */
export function scanSpendInputs(vins: TxVin[], ctx: TxScanContext): boolean;
/**
 * Returns whether the wallet owns this transaction (receive or spend).
 *
 * @param {TxScanInput} tx
 * @param {TxScanContext} ctx
 * @returns {boolean}
 */
export function ownsTx(tx: TxScanInput, ctx: TxScanContext): boolean;
/**
 * Batch `ownsTx` — one WASM receive scan for the whole array, then spend checks in JS.
 *
 * @param {TxScanInput[]} txs
 * @param {TxScanContext} ctx
 * @returns {boolean[]}
 */
export function ownsTxBatch(txs: TxScanInput[], ctx: TxScanContext): boolean[];
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
export function serializeTransaction(tx: TxToSerialize, headerOnly?: boolean): string;
/**
 * Compute the transaction prefix hash (`cn_fast_hash` of the header-only serialization).
 * Ported from `CnTransactions.get_tx_prefix_hash`.
 *
 * @param {TxToSerialize} tx - Transaction to hash.
 * @returns {string} 64-char hex prefix hash.
 */
export function getTransactionPrefixHash(tx: TxToSerialize): string;
/**
 * Serialize a transaction and compute its full hash.
 * Ported from `CnTransactions.serialize_tx_with_hash`.
 *
 * @param {TxToSerialize} tx - Transaction to serialize.
 * @returns {TxSerializeWithHash}
 */
export function serializeTransactionWithHash(tx: TxToSerialize): TxSerializeWithHash;
export const TX_EXTRA_TAG_PADDING: 0;
export const TX_EXTRA_TAG_PUBKEY: 1;
export const TX_EXTRA_NONCE: 2;
export const TX_EXTRA_MERGE_MINING_TAG: 3;
export const TX_EXTRA_MESSAGE_TAG: 4;
export const TX_EXTRA_MYSTERIOUS_MINERGATE_TAG: 222;
export const TX_EXTRA_TTL: 5;
export type TxExtra = {
    /**
     * - Extra field tag byte.
     */
    type: number;
    /**
     * - Payload bytes.
     */
    data: number[];
};
export type TxVout = {
    /**
     * - Output target type (`"02"` = key, `"03"` = tagged keys).
     */
    type: string;
    /**
     * - On-chain output public key (type `"02"`).
     */
    key?: string;
    /**
     * - On-chain keys (type `"03"`).
     */
    keys?: string[];
};
export type TxVin = {
    /**
     * - Key image hex (spend detection).
     */
    k_image?: string;
    /**
     * - Relative ring offsets (view-only spend detection).
     */
    key_offsets?: number[];
};
export type TxScanInput = {
    /**
     * - Transaction `extra` field as hex.
     */
    extraHex: string;
    /**
     * - Outputs to scan for incoming funds.
     */
    vouts: TxVout[];
    /**
     * - Inputs for spend / view-only detection.
     */
    vins?: TxVin[];
};
export type TxScanContext = {
    /**
     * - 64-char hex view secret key.
     */
    viewSecretHex: string;
    /**
     * - 64-char hex spend public key.
     */
    spendPublicHex: string;
    /**
     * - Spend secret when wallet can sign; enables key-image path.
     */
    spendSecretHex?: string;
    /**
     * - Key images known to belong to this wallet (spend path).
     */
    ownedKeyImages?: string[];
    /**
     * - Global output indexes owned (view-only path).
     */
    knownGlobalOutputIndexes?: number[];
};
export type ReceiveOutputChecks = {
    /**
     * - Derivation indices for `derive_public_key`.
     */
    indices: number[];
    /**
     * - On-chain output public keys (64-char hex).
     */
    keys: string[];
};
export type TxSerializeVinTarget = {
    /**
     * - Input type (`"input_to_key"` or `"input_to_deposit_key"`).
     */
    type: string;
    /**
     * - Input amount (uint64; pass large values as strings).
     */
    amount?: number | string;
    /**
     * - Relative ring offsets (`input_to_key`).
     */
    key_offsets?: number[];
    /**
     * - 64-char hex key image (`input_to_key`).
     */
    k_image?: string;
    /**
     * - Deposit output index (`input_to_deposit_key`).
     */
    outputIndex?: number | string;
    /**
     * - Deposit term in blocks (`input_to_deposit_key`).
     */
    term?: number | string;
    /**
     * - Expected signature count for `input_to_deposit_key`.
     */
    signatures?: number;
};
export type TxSerializeVoutTargetData = {
    /**
     * - 64-char hex output public key (`txout_to_key`).
     */
    key?: string;
    /**
     * - 64-char hex output keys (`txout_to_deposit_key`).
     */
    keys?: string[];
    /**
     * - Deposit term in blocks (`txout_to_deposit_key`).
     */
    term?: number | string;
};
export type TxSerializeVoutTarget = {
    /**
     * - Target type (`"txout_to_key"` or `"txout_to_deposit_key"`).
     */
    type: string;
    /**
     * - Target payload.
     */
    data: TxSerializeVoutTargetData;
};
export type TxSerializeVout = {
    /**
     * - Output amount (uint64; pass large values as strings).
     */
    amount: number | string;
    /**
     * - Output target.
     */
    target: TxSerializeVoutTarget;
};
export type TxToSerialize = {
    /**
     * - Transaction version (uint64).
     */
    version: number | string;
    /**
     * - Unlock time / block height (uint64).
     */
    unlock_time: number | string;
    /**
     * - Transaction inputs.
     */
    vin: TxSerializeVinTarget[];
    /**
     * - Transaction outputs.
     */
    vout: TxSerializeVout[];
    /**
     * - `extra` field as an even-length hex string.
     */
    extra: string;
    /**
     * - Per-input ring signatures (omitted when serializing header only).
     */
    signatures: string[][];
};
export type TxSerializeWithHash = {
    /**
     * - Full serialized transaction hex (prefix + signatures).
     */
    raw: string;
    /**
     * - `cn_fast_hash` of the full serialized transaction.
     */
    hash: string;
};
