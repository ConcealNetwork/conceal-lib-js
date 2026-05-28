import { cpSync, mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";

/** @type {string} */
const outDir = "pages-dist";

mkdirSync(outDir, { recursive: true });
cpSync("test", join(outDir, "test"), { recursive: true });
cpSync("src", join(outDir, "src"), { recursive: true });

// Skip Jekyll processing so static assets (including .wasm) are served as-is.
writeFileSync(join(outDir, ".nojekyll"), "");

writeFileSync(
  join(outDir, "index.html"),
  `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta http-equiv="refresh" content="0; url=./test/" />
  <title>conceal-lib-js</title>
</head>
<body>
  <p><a href="./test/">WASM test suite</a></p>
</body>
</html>
`,
);
