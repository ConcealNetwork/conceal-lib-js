#!/usr/bin/env node

import path from "node:path";
import { runPrebuild } from "../scripts/prebuild.mjs";

function printUsage() {
  console.log(`concealjs — Conceal Network crypto library CLI

Usage:
  npx concealjs --prebuild [--out <dir>]

Options:
  --prebuild       Bundle concealjs into your project (AMD / RequireJS / <script>)
  --out <dir>      Output directory (default: <cwd>/src/lib/concealjs)
  -h, --help       Show this help

Example:
  npx concealjs --prebuild
  npx concealjs --prebuild --out src/lib/concealjs

Output (under src/lib/concealjs by default):
  concealjs.js       Self-contained bundle (~260 KB, WASM inlined)
  concealjs.js.map   Source map
  index.d.ts         TypeScript types
  js/mnemonic.d.ts
  wasm/crypto/crypto.d.ts
  wasm/cypher/cypher.d.ts

Requires concealjs to be built first (npm install concealjs, or dev: npm run build in the package).

RequireJS:
  paths: { concealjs: "lib/concealjs/concealjs" }
  require(["concealjs"], function (cj) {
    cj.crypto.generate_keys(seedHex);
  });

TypeScript (paths in tsconfig):
  "paths": { "concealjs": ["./src/lib/concealjs/index.d.ts"] }
`);
}

function parseArgs(argv) {
  let prebuild = false;
  let outDir = path.join(process.cwd(), "src/lib/concealjs");
  let help = false;

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === "--prebuild") {
      prebuild = true;
    } else if (arg === "--out" && argv[i + 1]) {
      outDir = path.resolve(process.cwd(), argv[++i]);
    } else if (arg === "-h" || arg === "--help") {
      help = true;
    } else if (arg.startsWith("-")) {
      throw new Error(`Unknown option: ${arg}`);
    }
  }

  return { prebuild, outDir, help };
}

async function main() {
  const { prebuild, outDir, help } = parseArgs(process.argv.slice(2));

  if (help || !prebuild) {
    printUsage();
    process.exit(help ? 0 : 1);
  }

  const { outFile } = await runPrebuild({ outDir });
  console.log(`concealjs prebuild written to ${outDir}`);
  console.log(`  ${path.relative(process.cwd(), outFile)}`);
}

main().catch((err) => {
  console.error(err.message || err);
  process.exit(1);
});
