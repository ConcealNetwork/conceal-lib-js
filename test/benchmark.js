import * as address from "../src/js/address.js";
import * as cnutils from "../src/js/cnutils.js";
import {
  create_address,
  cn_fast_hash as wasmCnFastHash,
  decode_address as wasmDecodeAddress,
  encode_address as wasmEncodeAddress,
  encode_integrated_address as wasmEncodeIntegratedAddress,
} from "./wasm/crypto/crypto.js";

/** @typedef {Object} BenchmarkResult
 * @property {string} name - Short benchmark label.
 * @property {string} jsPath - JS API path timed.
 * @property {string} wasmPath - WASM API path timed.
 * @property {number} iterations - Loop count for bulk timing.
 * @property {number} jsBulkUs - Average microseconds per call (JS, bulk).
 * @property {number} wasmBulkUs - Average microseconds per call (WASM, bulk).
 * @property {number} jsSingleMs - Wall time for one JS call after warmup.
 * @property {number} wasmSingleMs - Wall time for one WASM call after warmup.
 * @property {"js" | "wasm" | "tie"} fasterBulk - Bulk winner (±5%).
 * @property {"js" | "wasm" | "tie"} fasterSingle - Single-call winner (±5%).
 * @property {string} [note] - Skip or parity note.
 */

const SEED = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

const PAYMENT_ID = "00112233445566aa";

const WARMUP = 100;
const TIE_RATIO = 0.05;

/**
 * @param {() => void} fn
 * @param {number} iterations
 * @returns {number} elapsed milliseconds
 */
function timeFn(fn, iterations) {
  const start = performance.now();
  for (let i = 0; i < iterations; i++) {
    fn();
  }
  return performance.now() - start;
}

/**
 * @param {() => void} fn
 * @returns {number} elapsed milliseconds for one invocation
 */
function timeSingle(fn) {
  const start = performance.now();
  fn();
  return performance.now() - start;
}

/**
 * Warm up JIT for both tiers before measuring.
 * @param {() => void} jsFn
 * @param {() => void} wasmFn
 * @param {number} [warmup]
 */
function warmup(jsFn, wasmFn, warmup = WARMUP) {
  for (let i = 0; i < warmup; i++) {
    jsFn();
    wasmFn();
  }
}

/**
 * @param {number} jsMs
 * @param {number} wasmMs
 * @returns {"js" | "wasm" | "tie"}
 */
function pickFaster(jsMs, wasmMs) {
  if (jsMs <= wasmMs * (1 - TIE_RATIO)) return "js";
  if (wasmMs <= jsMs * (1 - TIE_RATIO)) return "wasm";
  return "tie";
}

/**
 * @param {string} name
 * @param {string} jsPath
 * @param {string} wasmPath
 * @param {() => void} jsFn
 * @param {() => void} wasmFn
 * @param {number} iterations
 * @returns {BenchmarkResult}
 */
function benchPair(name, jsPath, wasmPath, jsFn, wasmFn, iterations) {
  warmup(jsFn, wasmFn);

  const jsSingleMs = timeSingle(jsFn);
  const wasmSingleMs = timeSingle(wasmFn);

  const jsTotalMs = timeFn(jsFn, iterations);
  const wasmTotalMs = timeFn(wasmFn, iterations);
  const jsBulkUs = (jsTotalMs / iterations) * 1000;
  const wasmBulkUs = (wasmTotalMs / iterations) * 1000;

  return {
    name,
    jsPath,
    wasmPath,
    iterations,
    jsBulkUs,
    wasmBulkUs,
    jsSingleMs,
    wasmSingleMs,
    fasterBulk: pickFaster(jsTotalMs, wasmTotalMs),
    fasterSingle: pickFaster(jsSingleMs, wasmSingleMs),
  };
}

/**
 * @param {Partial<BenchmarkResult> & Pick<BenchmarkResult, "name" | "jsPath" | "wasmPath" | "note">} row
 * @returns {BenchmarkResult}
 */
function skipRow(row) {
  return {
    iterations: 0,
    jsBulkUs: 0,
    wasmBulkUs: 0,
    jsSingleMs: 0,
    wasmSingleMs: 0,
    fasterBulk: "tie",
    fasterSingle: "tie",
    ...row,
  };
}

/**
 * Run JS vs WASM benchmarks for APIs with identical semantics.
 * @returns {Promise<BenchmarkResult[]>}
 */
export async function runBenchmarks() {
  const keys = create_address(SEED);
  const spendPub = keys.spend.pub;
  const viewPub = keys.view.pub;
  const plainAddr = address.encode_address(spendPub, viewPub);
  const integratedAddr = address.encode_integrated_address(
    spendPub,
    viewPub,
    PAYMENT_ID,
  );

  /** @type {BenchmarkResult[]} */
  const results = [];

  results.push(
    benchPair(
      "cn_fast_hash",
      "cnutils.cn_fast_hash",
      "crypto.cn_fast_hash",
      () => {
        cnutils.cn_fast_hash(SEED);
      },
      () => {
        wasmCnFastHash(SEED);
      },
      8000,
    ),
  );

  if (typeof wasmEncodeAddress === "function") {
    results.push(
      benchPair(
        "encode_address",
        "address.encode_address",
        "crypto.encode_address",
        () => {
          address.encode_address(spendPub, viewPub);
        },
        () => {
          wasmEncodeAddress(spendPub, viewPub);
        },
        3000,
      ),
    );
  } else {
    results.push(
      skipRow({
        name: "encode_address",
        jsPath: "address.encode_address",
        wasmPath: "crypto.encode_address",
        note: "SKIP — rebuild crypto WASM",
      }),
    );
  }

  if (typeof wasmEncodeIntegratedAddress === "function") {
    results.push(
      benchPair(
        "encode_integrated_address",
        "address.encode_integrated_address",
        "crypto.encode_integrated_address",
        () => {
          address.encode_integrated_address(spendPub, viewPub, PAYMENT_ID);
        },
        () => {
          wasmEncodeIntegratedAddress(spendPub, viewPub, PAYMENT_ID);
        },
        3000,
      ),
    );
  } else {
    results.push(
      skipRow({
        name: "encode_integrated_address",
        jsPath: "address.encode_integrated_address",
        wasmPath: "crypto.encode_integrated_address",
        note: "SKIP — rebuild crypto WASM",
      }),
    );
  }

  results.push(
    benchPair(
      "decode_address (standard)",
      "address.decode_address",
      "crypto.decode_address",
      () => {
        address.decode_address(plainAddr);
      },
      () => {
        wasmDecodeAddress(plainAddr);
      },
      4000,
    ),
  );

  const wasmIntegrated = wasmDecodeAddress(integratedAddr);
  if (wasmIntegrated?.intPaymentId === PAYMENT_ID) {
    results.push(
      benchPair(
        "decode_address (integrated)",
        "address.decode_address",
        "crypto.decode_address",
        () => {
          address.decode_address(integratedAddr);
        },
        () => {
          wasmDecodeAddress(integratedAddr);
        },
        4000,
      ),
    );
  } else {
    results.push(
      skipRow({
        name: "decode_address (integrated)",
        jsPath: "address.decode_address",
        wasmPath: "crypto.decode_address",
        note: "SKIP — rebuild crypto WASM for integrated payment ID",
      }),
    );
  }

  return results;
}

/**
 * @param {number} us
 * @returns {string}
 */
function formatUs(us) {
  if (us >= 1000) return `${(us / 1000).toFixed(2)} ms`;
  if (us >= 10) return `${us.toFixed(1)} µs`;
  return `${us.toFixed(2)} µs`;
}

/**
 * @param {number} ms
 * @returns {string}
 */
function formatSingleMs(ms) {
  if (ms >= 1) return `${ms.toFixed(2)} ms`;
  if (ms >= 0.01) return `${(ms * 1000).toFixed(1)} µs`;
  return "<10 µs";
}

/**
 * @param {number} a
 * @param {number} b
 * @returns {string}
 */
function formatRatio(a, b) {
  if (b <= 0) return "—";
  return `${(a / b).toFixed(2)}×`;
}

/**
 * @param {"js" | "wasm" | "tie"} winner
 * @returns {string}
 */
function winnerText(winner) {
  if (winner === "js") return "JS";
  if (winner === "wasm") return "WASM";
  return "~tie";
}

/**
 * @param {Document} doc
 * @param {string} text
 * @param {"js" | "wasm" | "tie"} [winner]
 * @returns {HTMLTableCellElement}
 */
function cell(doc, text, winner) {
  const td = doc.createElement("td");
  td.textContent = text;
  if (winner === "js") td.className = "bench-winner-js";
  else if (winner === "wasm") td.className = "bench-winner-wasm";
  return td;
}

/**
 * Render benchmark rows into a container element.
 * @param {HTMLElement} container
 * @param {BenchmarkResult[]} results
 */
export function renderBenchmarkResults(container, results) {
  container.innerHTML = "";

  const meta = document.createElement("p");
  meta.className = "bench-meta";
  meta.textContent =
    "WASM module already initialized (init() paid before tests). " +
    "Bulk = warmup then N timed loops (avg/op). " +
    "Single = one call after warmup — shows JS↔WASM boundary cost not amortized.";
  container.appendChild(meta);

  const table = document.createElement("table");
  table.className = "bench-table";

  const thead = document.createElement("thead");
  thead.innerHTML = `
    <tr>
      <th rowspan="2">Function</th>
      <th rowspan="2">N</th>
      <th colspan="4">Bulk (avg per call)</th>
      <th colspan="4">Single call (1×)</th>
    </tr>
    <tr>
      <th>JS</th>
      <th>WASM</th>
      <th>Winner</th>
      <th>JS/WASM</th>
      <th>JS</th>
      <th>WASM</th>
      <th>Winner</th>
      <th>JS/WASM</th>
    </tr>
  `;
  table.appendChild(thead);

  const tbody = document.createElement("tbody");

  for (const row of results) {
    const tr = document.createElement("tr");
    tr.title = `${row.jsPath} vs ${row.wasmPath}`;

    const nameTd = document.createElement("td");
    nameTd.textContent = row.name;
    tr.appendChild(nameTd);

    const nTd = document.createElement("td");
    nTd.textContent = row.note ? "—" : row.iterations.toLocaleString();
    tr.appendChild(nTd);

    if (row.note) {
      const skipTd = document.createElement("td");
      skipTd.colSpan = 8;
      skipTd.className = "bench-skip";
      skipTd.textContent = row.note;
      tr.appendChild(skipTd);
      tbody.appendChild(tr);
      continue;
    }

    tr.appendChild(cell(document, formatUs(row.jsBulkUs)));
    tr.appendChild(cell(document, formatUs(row.wasmBulkUs)));
    tr.appendChild(cell(document, winnerText(row.fasterBulk), row.fasterBulk));
    tr.appendChild(cell(document, formatRatio(row.jsBulkUs, row.wasmBulkUs)));

    tr.appendChild(cell(document, formatSingleMs(row.jsSingleMs)));
    tr.appendChild(cell(document, formatSingleMs(row.wasmSingleMs)));
    tr.appendChild(
      cell(document, winnerText(row.fasterSingle), row.fasterSingle),
    );
    tr.appendChild(
      cell(document, formatRatio(row.jsSingleMs, row.wasmSingleMs)),
    );

    tbody.appendChild(tr);
  }

  table.appendChild(tbody);
  container.appendChild(table);
}
