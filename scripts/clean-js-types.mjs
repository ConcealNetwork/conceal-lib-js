/**
 * Remove JS-layer declaration files before `tsc` regenerates them.
 * Avoids TS5055 (emit would overwrite an existing sibling .d.ts).
 */

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const PKG_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

const STALE_DTS = [
  "src/js/mnemonic.d.ts",
  "src/js/cnutils.d.ts",
  "src/js/random.d.ts",
  "src/js/cn.d.ts",
  "src/js/transactions.d.ts",
  "src/js/base58.d.ts",
  "src/js/address.d.ts",
  "src/js/tiers/nacl.d.ts",
  "src/js/tiers/biginteger.d.ts",
  "src/js/tiers/sha3.d.ts",
];

for (const rel of STALE_DTS) {
  const file = path.join(PKG_ROOT, rel);
  try {
    fs.unlinkSync(file);
  } catch (err) {
    if (err.code !== "ENOENT") throw err;
  }
}
