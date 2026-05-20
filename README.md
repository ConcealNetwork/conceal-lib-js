# concealjs — Cryptographic primitives for Conceal Network

`conceal-lib-js` is the one-stop npm package for every cryptographic function used by
`conceal-web-wallet`.  Heavy operations are compiled from Rust to WebAssembly;
`CnUtils`-style helpers, Keccak, and string-heavy work stay in plain JavaScript
(and TweetNaCl CN extensions) where that wins on latency.

---

## Use

### Bundlers and Node (ESM)

```js
import { mnemonic, cnutils, crypto, cypher } from "concealjs";
```

Works with Vite, webpack, Rollup, and Node when your toolchain resolves the package `import` condition. WASM is loaded by the bundler automatically.

### AMD / RequireJS (e.g. conceal-web-wallet)

Projects that serve TypeScript/AMD with RequireJS and no app bundler should **vendor** a prebuilt copy into the repo:

```sh
npm install concealjs
npx concealjs --prebuild
```

By default this writes `src/lib/concealjs/` (single `concealjs.js` ~260 KB with WASM inlined, plus `.d.ts` files). Use a custom directory if needed:

```sh
npx concealjs --prebuild --out src/lib/concealjs
```

CLI help: `npx concealjs --help`.


#### TypeScript

Verify concealjs.d.ts in included in src/lib/concealjs

If you used `--out`, change the `concealjs` path to match that folder.

#### index.html

Add before RequireJS:

```js
<script src="lib/concealjs/concealjs.js"></script>
```

Load and use the global API:

```ts
const result = concealjs.crypto.derive_secret_key(derivation, out_index, sec);
```

---

## Full API reference

### Namespace `mnemonic` — plain JavaScript (`js/mnemonic.js`)

> Implemented in plain JS — no WASM boundary overhead.
> Benchmarked at ~2.8× faster than the equivalent Rust WASM build.

| Function | Parameters | Returns | Notes |
|---|---|---|---|
| `mn_encode(str, wordset_name?)` | `str`: 64-char hex seed; `wordset_name`: `'english'` (default) / `'electrum'` / `'japanese'` | 25-word mnemonic string | Throws on invalid input |
| `mn_decode(str, wordset_name?)` | `str`: space-separated mnemonic (25 words for English); `wordset_name`: same options | 64-char hex seed string | Verifies checksum word; throws on mismatch |
| `mn_random(bits)` | `bits`: multiple of 32 — typically `256` | hex string of length `bits/4` | Browser only — uses `window.crypto.getRandomValues` |

---

### Namespace `cnutils` — JavaScript (`src/js/cnutils.js`)

> Port of `CnUtils` from `conceal-web-wallet/src/model/Cn.ts`.
> `cn_fast_hash` uses **Keccak-256** from `src/js/tiers/sha3.js` (same as the wallet’s `keccak_256`, not SHA3-256).
> Curve ops use `src/js/tiers/nacl.js` (`nacl.ll`). Scalar helpers (`hash_to_scalar`, `sc_add`, `sc_sub`) use `crypto` WASM.

Exported constant: `STRUCT_SIZES`.

| Function | Parameters | Returns | Notes |
|---|---|---|---|
| `hextobin` / `bintohex` | hex ↔ bytes | `Uint8Array` / hex | |
| `swapEndian` / `swapEndianC` | string | string | Byte or char order |
| `d2h` / `d2s` / `h2d` / `d2b` | integer / hex | hex or number | `JSBigInt` internally; `d2s` = endian-swapped scalar |
| `encode_varint` / `encode_varint_term` | `number \| string \| JSBigInt` | hex | CryptoNote varint |
| `cn_fast_hash` | hex string | 64-char hex | `keccak_256(hextobin(input))` via `tiers/sha3.js` |
| `derivation_to_scalar` | 64-char derivation + index | 64-char scalar | WASM `hash_to_scalar` |
| `valid_hex` / `hex_xor` / `trimRight` / `padLeft` | — | — | Utilities |
| `sec_key_to_pub` / `ge_scalarmult*` / `ge_add` / `ge_sub` / `ge_neg` | 64-char hex | 64-char hex | `nacl.ll` |
| `ge_double_scalarmult_base_vartime` | `c`, `P`, `r` | 64-char hex | |
| `ge_double_scalarmult_postcomp_vartime` | `r`, `P`, `c`, `I` | 64-char hex | Needs `crypto.hash_to_ec` (rebuild WASM) |
| `decompose_amount_into_digits` | amount | `JSBigInt[]` | |
| `decode_rct_ecdh` / `encode_rct_ecdh` | `{ mask, amount }`, key | `{ mask, amount }` | WASM scalar add/sub |

---

### Namespace `crypto` — Rust WASM (`rust/crypto/`)

> All functions accept and return **hex strings** (lowercase).
> Function names match `conceal-web-wallet/src/model/Cn.ts` exactly.

#### Hash

| Function | Parameters | Returns | C++ reference |
|---|---|---|---|
| `cn_fast_hash(data_hex)` | hex string (any length) | 64-char hex (Keccak-256) | `hash-ops.h: cn_fast_hash` |
| `hash_to_scalar(data_hex)` | hex string (any length) | 64-char hex scalar | `cn_fast_hash` then `sc_reduce32` |

#### Scalar arithmetic (`crypto-ops.h`)

All scalars are 64-char hex (32-byte little-endian integers mod Ed25519 group order *l*).

| Function | Parameters | Returns | Notes |
|---|---|---|---|
| `sc_reduce32(hex)` | 64-char hex | 64-char hex | Reduce mod *l* |
| `sc_add(a, b)` | two 64-char hex scalars | 64-char hex | `(a + b) mod l` |
| `sc_sub(a, b)` | two 64-char hex scalars | 64-char hex | `(a − b) mod l` |
| `sc_mulsub(a, b, c)` | three 64-char hex scalars | 64-char hex | `(c − a·b) mod l` |
| `sc_0()` | — | 64-char hex `"00…00"` | Zero scalar |
| `sc_check(hex)` | 64-char hex | `boolean` | `true` if scalar is canonical (< *l*) |

#### Edwards curve group operations (`crypto-ops.h`)

All points are 64-char hex (32-byte compressed Edwards y format).

| Function | Parameters | Returns | Notes |
|---|---|---|---|
| `ge_scalarmult_base(scalar_hex)` | 64-char hex scalar | 64-char hex point | `scalar × B` — also serves as `sec_key_to_pub` |
| `ge_scalarmult(point_hex, scalar_hex)` | 64-char hex point + scalar | 64-char hex point | `scalar × point` |
| `ge_mul8(point_hex)` | 64-char hex point | 64-char hex point | Multiply by cofactor 8 |
| `ge_add(a_hex, b_hex)` | two 64-char hex points | 64-char hex point | Edwards point addition |
| `ge_tobytes(point_hex)` | 64-char hex point | 64-char hex point | Validates point is on curve |
| `ge_p3_tobytes(point_hex)` | 64-char hex point | 64-char hex point | Alias for `ge_tobytes` |
| `ge_frombytes_vartime(point_hex)` | 64-char hex point | 64-char hex point | Decompress + re-compress (validates) |

#### High-level key operations (`crypto.h`)

| Function | Parameters | Returns | C++ reference |
|---|---|---|---|
| `generate_keys(seed_hex)` | 64-char hex seed | `{ sec: hex, pub: hex }` | `sc_reduce32(seed)` + `ge_scalarmult_base(sec)` |
| `generate_key_derivation(pub_hex, sec_hex)` | two 64-char hex keys | 64-char hex derivation | `8 × (sec · pub_point)` — DH shared key |
| `derive_public_key(deriv_hex, index, base_pub_hex)` | derivation + u32 index + 64-char hex pub | 64-char hex pub | `base_pub + H(derivation‖varint(index)) · B` |
| `derive_secret_key(deriv_hex, index, base_sec_hex)` | derivation + u32 index + 64-char hex sec | 64-char hex sec | `sc_add(base_sec, H(derivation‖varint(index)))` |

#### Address (`CryptoNoteBasicImpl.h`, `crypto.h`)

| Function | Parameters | Returns | Notes |
|---|---|---|---|
| `create_address(seed_hex)` | 64-char hex seed | `{ spend: {sec, pub}, view: {sec, pub}, public_addr: string }` | Monero-compatible: `view = generate_keys(cn_fast_hash(spend.sec))` |
| `decode_address(address)` | Base58 Conceal address string | `{ spend: hex, view: hex, intPaymentId: null }` | Validates checksum; throws on invalid prefix or checksum |

#### Conceal Network constants baked in

| Constant | Value | Purpose |
|---|---|---|
| Address prefix | `31444` (varint `d4f501`) | Standard CCX mainnet address |
| Integrated address prefix | `31445` | Payment-ID address |
| Subaddress prefix | `31446` | Subaddress |
| Address checksum | first 4 bytes of `cn_fast_hash(prefix + spend + view)` | Embedded in every address |

---

### Namespace `cypher` — Rust WASM (`rust/cypher/`)

> Stream ciphers — encrypt and decrypt are the same operation (XOR with keystream).
> IETF nonce format: 32-byte key + 12-byte nonce + 32-bit counter starting at 0.

| Function | Parameters | Returns | Notes |
|---|---|---|---|
| `chacha8(key, nonce, data)` | `key`: `Uint8Array[32]`; `nonce`: `Uint8Array[12]`; `data`: `Uint8Array` | `Uint8Array` | ChaCha8 (8 rounds). Throws on wrong key/nonce size |
| `chacha12(key, nonce, data)` | `key`: `Uint8Array[32]`; `nonce`: `Uint8Array[12]`; `data`: `Uint8Array` | `Uint8Array` | ChaCha12 (12 rounds). Throws on wrong key/nonce size |

---

## Implementation / runtime split

| Function | Module | Runtime | Reason |
|---|---|---|---|
| `mn_encode` | `mnemonic` | **plain JS** | String-heavy; JS JIT ~2.8× faster than WASM boundary |
| `mn_decode` | `mnemonic` | **plain JS** | Same as above |
| `mn_random` | `mnemonic` | **plain JS** | Thin wrapper over `window.crypto` |
| `hextobin`, `encode_varint`, `ge_add`, … | `cnutils` | **plain JS** (+ `nacl.ll`) | `CnUtils` helpers |
| `cn_fast_hash` | `cnutils` | **plain JS** (`tiers/sha3.js`) | Same Keccak as wallet; faster than WASM boundary for typical hex |
| `cn_fast_hash` | `crypto` | **Rust WASM** | Same digest; use when already in WASM-only path |
| `derivation_to_scalar`, RCT ECDH | `cnutils` → `crypto` | **mixed** | JS glue + WASM scalars |
| `hash_to_scalar` | `crypto` | **Rust WASM** | Hash + reduce |
| `sc_reduce32` | `crypto` | **Rust WASM** | Modular reduction |
| `sc_add / sc_sub / sc_mulsub / sc_0 / sc_check` | `crypto` | **Rust WASM** | Scalar field arithmetic |
| `ge_scalarmult_base` | `crypto` | **Rust WASM** | EC base-point multiplication |
| `ge_scalarmult / ge_mul8 / ge_add` | `crypto` | **Rust WASM** | EC group operations |
| `ge_tobytes / ge_p3_tobytes / ge_frombytes_vartime` | `crypto` | **Rust WASM** | Point serialisation |
| `generate_keys` | `crypto` | **Rust WASM** | Key generation |
| `generate_key_derivation` | `crypto` | **Rust WASM** | DH key derivation |
| `derive_public_key / derive_secret_key` | `crypto` | **Rust WASM** | Sub-key derivation |
| `create_address / decode_address` | `crypto` | **Rust WASM** | Address encode/decode |
| `chacha8 / chacha12` | `cypher` | **Rust WASM** | Stream cipher — compute-heavy |

---

## Known test vector (seed `0x01` × 32)

Used in `address::tests::known_vector_seed_ones` to cross-check against
`conceal-web-wallet`'s `Cn.create_address("0101…01")`.

| Field | Value |
|---|---|
| `spend.sec` | `0101010101010101010101010101010101010101010101010101010101010101` |
| `spend.pub` | `130ae82201d7072e6fbfc0a1884fb54636554d14945b799125cf7ce38d477f51` |
| `view.sec` | `eb51211073fdd85629dda967a86ead8717884c2d66667c67a90508214bd8ba0c` |
| `view.pub` | `fa17d335e10b66cc28e09e2de59dc7e8a3d11bcf579d6d493b94c3d1f2081562` |
| `public_addr` | `ccx7DPvKYficy3QUqegFJFELGa3CE61AKGJRQgyBMe6xCxcbqXfRa722ucLqFsm4hiTPfzf7JTzwxTLEp2jR4BGm1JmVe2rDkq` |

To verify against the web wallet, open the browser console and run:
```js
Cn.create_address("0101010101010101010101010101010101010101010101010101010101010101")
```

---
# DEVELOPMENT

## Prerequisites

```sh
curl https://sh.rustup.rs -sSf | sh
rustup target add wasm32-unknown-unknown
cargo install wasm-pack
sudo apt install clang lld
```

---

## Build

```sh
npm run build            # crypto + cypher WASM → src/wasm and src/wasm-browser
npm run build:crypto     # cd rust/crypto && wasm-pack build …
npm run build:cypher     # cd rust/cypher && wasm-pack build …
```

WASM outputs land in `src/wasm/<crate>/` (git-ignored). `cnutils` does not use WASM for `cn_fast_hash` (uses `src/js/tiers/sha3.js`).

## Native unit tests

```sh
cargo test --workspace   # 29 tests: 16 crypto + 6 cypher + 7 mnemonic
```

## JS integration tests

Browser suite (`test/`): mnemonic, **cnutils**, crypto, cypher.

```sh
npm run build              # src/wasm for cnutils + package consumers
npm run build:test         # test/wasm (web target) for crypto/cypher suites
npx --yes serve .
```

Open `http://localhost:3000/test/` (or the port `serve` prints).

Use `npx serve .` from the repo root (serves `serve.json` so `.wasm` files get
`Content-Type: application/wasm`).


---

## Workspace layout

```
concealjs/
├── Cargo.toml              # Rust workspace root
├── package.json            # npm package (main: js/index.js)
├── rustfmt.toml
│
├── rust/                   # all Rust crates → compiled to WASM
│   ├── mnemonic/           # mn_encode / mn_decode / mn_random (Rust, kept for reference)
│   ├── crypto/             # keccak, EC ops, key derivation, address
│   └── cypher/             # chacha8 / chacha12 stream ciphers
│
├── src/                    # public JS/TS API layer (the npm package)
│   ├── index.js            # re-exports: mnemonic, cnutils, crypto, cypher
│   ├── index.d.ts
│   ├── js/
│   │   ├── mnemonic.js
│   │   ├── cnutils.js      # CnUtils port
│   │   └── tiers/          # biginteger.js, nacl.js, sha3.js
│   └── wasm/               # wasm-pack bundler outputs (git-ignored)
│       ├── crypto/
│       └── cypher/
│
└── test/                   # browser integration tests
    ├── test-all.js
    ├── test-cnutils.js
    ├── test-crypto.js
    ├── test-mnemonic.js
    └── wasm/               # web-target WASM for test page (git-ignored)
```


