# concealjs — Rust/WASM webwallet modules

Rust cryptographic primitives compiled to WebAssembly, published as the `concealjs` npm package.

## Workspace layout

```
concealjs/
├── Cargo.toml              # Rust workspace root
├── mnemonic/               # mnemonic encode/decode (ported from Mnemonics.cpp)
├── cypher/                 # chacha8 / chacha12 (TODO)
├── crypto/                 # keccak256 / random key (TODO)
├── js/                     # ← the concealjs npm package
│   ├── package.json        #   name: "concealjs"
│   ├── index.js            #   re-exports each module as a namespace
│   ├── index.d.ts          #   aggregated TypeScript types
│   └── wasm/               #   wasm-pack bundler outputs (git-ignored)
│       ├── mnemonic/
│       ├── cypher/         #   (TODO)
│       └── crypto/         #   (TODO)
└── test/                   # dev-only browser test harness
    ├── index.html
    ├── test-all.js
    ├── test-mnemonic.js
    └── pkg/                # wasm-pack web outputs (git-ignored)
        └── mnemonic/
```

## Prerequisites

```sh
# Rust toolchain
curl https://sh.rustup.rs -sSf | sh
rustup target add wasm32-unknown-unknown

# wasm-pack
cargo install wasm-pack
```

## Build — production (concealjs npm package)

Each Rust crate is compiled with `--target bundler` (compatible with vite / webpack):

```sh
cd js && npm run build
```

Which expands to:

```sh
cd mnemonic && wasm-pack build --target bundler --out-dir ../js/wasm/mnemonic
# cd cypher && wasm-pack build --target bundler --out-dir ../js/wasm/cypher  (TODO)
# cd crypto  && wasm-pack build --target bundler --out-dir ../js/wasm/crypto  (TODO)
```

## Build — dev/test (browser harness)

Uses `--target web` so the test page works without a bundler:

```sh
cd mnemonic && wasm-pack build --target web --out-dir ../test/pkg/mnemonic
```

Then serve:

```sh
cd test && python3 -m http.server 8080
# open http://localhost:8080
```

## Run native unit tests

```sh
cargo test -p mnemonic
```

## Usage in a TypeScript project

```typescript
import { mnemonic } from "concealjs";

// 1. raw entropy (64-char hex, 256 bits)
const entropy: string = mnemonic.mn_random(256);

// 2. entropy → valid ed25519 scalar (done externally via sc_reduce32)

// 3. private spend key hex → 25-word seed phrase
const phrase: string  = mnemonic.mn_encode(spendKeyHex);

// 4. seed phrase → private spend key hex
const key: string     = mnemonic.mn_decode(phrase);
```

All functions throw a descriptive string on invalid input.

## API — mnemonic

| Function | Input | Output |
|---|---|---|
| `mn_random(bits: number)` | bit count (multiple of 32, typically 256) | hex string of length bits/4 |
| `mn_encode(hex_key: string)` | 64-char hex private spend key | 25-word mnemonic string |
| `mn_decode(mnemonic: string)` | 25-word mnemonic string | 64-char hex private spend key |
