/**
 * Headless Node runner for the crypto test suites.
 *
 * The browser harness (`test/index.html` + `test/test-all.js`) stays the
 * interactive source of truth for the assertions and the benchmarks; this
 * runner executes the SAME suites with a counting `log` callback and exits
 * non-zero when any check fails, so CI can gate on it:
 *
 *   npm test
 *
 * The suites import browser-target WASM modules that only exist after
 * `npm run build:test`; `test/node/hooks.mjs` redirects those imports to the
 * committed bundler-target WASM (loaded via --experimental-wasm-modules).
 */
import { register } from "node:module";

await register(new URL("./node/hooks.mjs", import.meta.url), import.meta.url);

// Minimal browser-ish globals for the JS tiers: mn_random reads globalThis.crypto
// (Node provides webcrypto as globalThis.crypto) and window.alerts on entropy
// failure. Scoped to this runner only — the library itself stays unchanged.
if (typeof globalThis.window === "undefined") {
  globalThis.window = {
    crypto: globalThis.crypto,
    alert: (message) => {
      throw new Error(String(message));
    },
  };
}

const SUITES = [
  { name: "mnemonic", run: () => import("./test-mnemonic.js").then((m) => m.runMnemonicTests) },
  { name: "cnutils", run: () => import("./test-cnutils.js").then((m) => m.runCnutilsTests) },
  { name: "crypto", run: () => import("./test-crypto.js").then((m) => m.runCryptoTests) },
  {
    name: "transactions",
    run: () => import("./test-transactions.js").then((m) => m.runTransactionsTests),
  },
  { name: "address", run: () => import("./test-address.js").then((m) => m.runAddressTests) },
  { name: "cn", run: () => import("./test-cn.js").then((m) => m.runCnTests) },
  { name: "cypher", run: () => import("./test-cypher.js").then((m) => m.runCypherTests) },
  { name: "secretbox", run: () => import("./test-secretbox.js").then((m) => m.runSecretboxTests) },
];

let totalPassed = 0;
let totalFailed = 0;
const failedSuites = [];

for (const suite of SUITES) {
  console.log(`\n── ${suite.name} ──`);
  let passed = 0;
  let failed = 0;
  const log = (msg, ok) => {
    if (ok) {
      passed += 1;
    } else {
      failed += 1;
      console.log(`  ✗ ${msg}`);
    }
  };

  try {
    const run = await suite.run();
    await run(log);
  } catch (e) {
    failed += 1;
    console.log(`  ✗ suite crashed: ${e}`);
  }

  // A suite that runs without crashing must log at least one check — otherwise
  // a silent no-op suite would masquerade as a pass.
  if (passed === 0 && failed === 0) {
    failed += 1;
    console.log("  ✗ suite logged no checks");
  }

  totalPassed += passed;
  totalFailed += failed;
  if (failed === 0) {
    console.log(`  ${passed} passed`);
  } else {
    failedSuites.push(suite.name);
    console.log(`  ${passed} passed, ${failed} FAILED`);
  }
}

console.log(`\n${totalPassed} passed, ${totalFailed} failed`);
if (totalFailed > 0) {
  console.error(`failing suites: ${failedSuites.join(", ")}`);
  process.exitCode = 1;
}
