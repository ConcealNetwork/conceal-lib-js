/**
 * Bundle concealjs for AMD / RequireJS / script-tag use (no app bundler required).
 * Writes a self-contained IIFE (+ AMD define) and TypeScript declarations.
 */

import * as esbuild from "esbuild";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const PKG_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

const TYPE_FILES = [
  "index.d.ts",
  "js/mnemonic.d.ts",
  "js/cnutils.d.ts",
  "wasm/crypto/crypto.d.ts",
  "wasm/cypher/cypher.d.ts",
];


/**
 * @param {{ outDir: string }} options
 */
export async function runPrebuild({ outDir }) {
  const entry = path.join(PKG_ROOT, "scripts/prebuild-entry.mjs");

  if (!fs.existsSync(path.join(PKG_ROOT, "src/wasm-browser/crypto/crypto_bg.wasm"))) {
    throw new Error(
      "Browser WASM not built. Run `npm run build` inside the concealjs package first.",
    );
  }

  await fs.promises.mkdir(outDir, { recursive: true });

  await esbuild.build({
    entryPoints: [entry],
    bundle: true,
    platform: "browser",
    format: "iife",
    globalName: "concealjs",
    outfile: path.join(outDir, "concealjs.js"),
    target: ["es2020"],
    minify: true,
    sourcemap: true,
    loader: { ".wasm": "binary" },
    conditions: ["browser"],
    plugins: [
      {
        name: "prebuild-browser-shims",
        setup(build) {
          build.onResolve({ filter: /^crypto$/ }, () => ({
            path: path.join(PKG_ROOT, "scripts/stub-node-crypto.cjs"),
          }));
        },
      },
    ],
    footer: {
      js: "if(typeof define==='function'&&define.amd){define(function(){return concealjs;});}",
    },
    logLevel: "silent",
  });

  const outFile = path.join(outDir, "concealjs.js");

  for (const rel of TYPE_FILES) {
    const src = path.join(PKG_ROOT, "src", rel);
    const dest = path.join(outDir, rel);
    await fs.promises.mkdir(path.dirname(dest), { recursive: true });
    await fs.promises.copyFile(src, dest);
  }

  const globalDts = `type ConcealJsGlobal = {
  crypto: typeof import("./wasm/crypto/crypto");
  cypher: typeof import("./wasm/cypher/cypher");
  mnemonic: typeof import("./js/mnemonic");
  cnutils: typeof import("./js/cnutils");
};

declare global {
  const concealjs: ConcealJsGlobal;

  interface Window {
    concealjs: ConcealJsGlobal;
  }
}

export {};
`;

  await fs.promises.writeFile(path.join(outDir, "concealjs.d.ts"), globalDts);

  const readmePath = path.join(PKG_ROOT, "README.md");
  const readme = await fs.promises.readFile(readmePath, "utf8");
  const devMarker = "\n---\n# DEVELOPMENT";
  const devIdx = readme.indexOf(devMarker);
  if (devIdx === -1) {
    throw new Error(`${readmePath}: expected DEVELOPMENT section marker not found`);
  }
  await fs.promises.writeFile(
    path.join(outDir, "README.md"),
    `${readme.slice(0, devIdx).trimEnd()}\n`,
  );

  const pkg = {
    name: "concealjs-prebuilt",
    private: true,
    main: "concealjs.js",
    types: "concealjs.d.ts",
  };
  await fs.promises.writeFile(
    path.join(outDir, "package.json"),
    JSON.stringify(pkg, null, 2) + "\n",
  );

  return { outDir, outFile };
}
