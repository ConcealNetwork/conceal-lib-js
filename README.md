# concealjs — Cryptographic primitives for Conceal Network

`concealjs` is the one-stop npm package for every cryptographic function used by
`conceal-web-wallet`.  Heavy operations are compiled from Rust to WebAssembly;
simple string operations stay in plain JavaScript where JIT compilation wins.

```
import { mnemonic, crypto, cypher } from "concealjs";
```

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
├── js/                     # public JS/TS API layer (the npm package)
│   ├── index.js            # re-exports: mnemonic, crypto, cypher namespaces
│   ├── index.d.ts          # aggregated TypeScript declarations
│   ├── mnemonic.js         # plain-JS mnemonic (2.8× faster than WASM for string ops)
│   └── wasm/               # wasm-pack bundler outputs (git-ignored)
│       ├── crypto/
│       └── cypher/
│
└── tests/                  # JS integration tests (populated per phase)
```

---

## Prerequisites

```sh
curl https://sh.rustup.rs -sSf | sh
rustup target add wasm32-unknown-unknown
cargo install wasm-pack
```

---

## Build

```sh
npm run build            # builds all three WASM crates
npm run build:crypto     # cd rust/crypto && wasm-pack build …
npm run build:cypher     # cd rust/cypher && wasm-pack build …
npm run build:mnemonic   # cd rust/mnemonic && wasm-pack build …
```

All WASM outputs land in `js/wasm/<crate>/` (git-ignored).

## Native unit tests

```sh
cargo test --workspace   # 29 tests: 16 crypto + 6 cypher + 7 mnemonic
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
| `cn_fast_hash` | `crypto` | **Rust WASM** | Keccak-256 — compute-heavy |
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
