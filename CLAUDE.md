# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working in this repository.

## Repository

`conceal-lib-js` — Rust → WebAssembly crypto primitives for Conceal (CCX). Rust sources are compiled with `wasm-pack` to `src/wasm` (Node) and `src/wasm-browser` (browser); the committed WASM artifacts mean `npm ci` / `npm run types` / `npm run lint` work **without** rebuilding. Rebuild WASM only after editing Rust.

## Commands

```bash
npm ci                      # install deps (no Rust toolchain needed; WASM committed)
npm run build               # wasm-pack build → src/wasm + src/wasm-browser (needs wasm-pack + clang)
npm run types               # tsc --noEmit
npm run lint                # Biome lint (lint:fix to autofix)
npm run format              # Biome format (format:fix to write)
npm test                    # headless Node run of the test/ suites (see below)
npm run release             # build + types + npm pack (produces the release tarball)
```

WASM rebuild (only after editing Rust): `npm run build` — requires `wasm-pack` and `clang` (both must be installed). Do not rebuild unless you changed Rust sources; the committed artifacts are the source of truth for downstream consumers.

Quality gate before completing changes: `npm run types && npm run lint && npm test`.

## Tests

The suites in `test/` (`test-mnemonic`, `test-cnutils`, `test-crypto`, `test-transactions`, `test-address`, `test-cn`, `test-cypher`, `test-secretbox`) run two ways:

- **`npm test`** — headless Node (`test/run-node.mjs`), gated in CI (`ci.yml`). The suites' browser-target WASM imports (`./wasm/crypto/crypto.js`, `./wasm/cypher/cypher.js`, which only exist after `npm run build:test`) are redirected by `test/node/hooks.mjs` to the committed bundler-target shims in `test/node/`, loaded via `node --experimental-wasm-modules`. The runner shims `window` for `mn_random` (Node provides webcrypto). It exits non-zero on any failure and skips the DOM benchmarks.
- **`test/index.html`** — the interactive browser harness (needs `npm run build:test` first; also runs the benchmarks). Stay the guideline when adding checks: add them to the shared suite files so BOTH runners execute them.

When adding or changing behavior covered by a suite, update the suite once — both runners pick it up. CI (`ci.yml`) runs lint + types + tests on every PR and push to `master`.

## Conventions & gotchas

- **Biome only** (no ESLint/Prettier).
- **Committed WASM artifacts are authoritative.** Never edit generated files under `src/wasm*/` by hand — regenerate via `npm run build` from the Rust sources.
- **On every `@biomejs/biome` update — follow this workflow in order:**
  1. **Plan** to update the `$schema` URL in `biome.json` to the new version in the same change. Dependabot only bumps `package.json` — it never touches `biome.json`, so this is always a manual follow-up. A stale `$schema` makes Biome emit an `info` diagnostic ("Expected X, Found Y … run `biome migrate`") on every lint run.
  2. **Before editing, check the web for the new schema:** fetch `https://biomejs.dev/schemas/<NEW_VERSION>/schema.json` and confirm it exists (HTTP 200), is valid JSON, and is a JSON Schema document (`$schema` key, non-trivial `properties`). This catches a missing/typo'd release doc and lets you diff structure for breaking changes.
  3. **Consider breaking changes** between old and new schema (removed/renamed properties, changed enums, new required fields). Patch bumps (x.y.Z) are config-compatible; minor (x.Y.0) and especially major (X.0.0) need a real diff. Read the Biome changelog + the schema diff.
  4. **If breaking changes are introduced:** try a PR with the updated `$schema` **and** adapt `biome.json` config keys to the new schema (rename/migrate/remove deprecated fields — run `biome migrate` if available, then hand-verify). Land both the schema URL and the config adaptation in one change.
  5. **If Biome still emits errors after adaptation** (lint/check/types fail on config the new Biome can't reconcile): consider **downgrading `@biomejs/biome` back** to the prior working version and **stop for admin review** — surface the exact errors, the version pair, and the unresolvable config conflict. Do not force a broken upgrade through.
  6. Always run `npm run lint` after the schema edit to confirm the diagnostic clears and nothing regressed.
