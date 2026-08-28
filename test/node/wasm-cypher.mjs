/**
 * Node shim for the browser-target `./wasm/cypher/cypher.js` import used by the
 * test suites (`test/wasm` only exists after `npm run build:test`, which needs a
 * Rust toolchain). Re-exports the committed bundler-target WASM build — already
 * initialized at import time, so the web-target module's default `init()` is a
 * no-op.
 */
export * from "../../src/wasm/cypher/cypher.js";
export default async function init() {}
