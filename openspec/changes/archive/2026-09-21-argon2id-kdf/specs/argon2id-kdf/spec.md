## Purpose

Provide a low-level Argon2id key-derivation primitive for Conceal wallet tooling. Callers supply password and salt as hex-encoded bytes; the library returns a fixed 32-byte derived key as lowercase hex. Envelope formats and password policy live in conceal-wallet-sdk.

## ADDED Requirements

### Requirement: Argon2id derivation API
The library SHALL export `crypto.argon2id(passwordHex, saltHex, memoryKiB, iterations, parallelism)` that derives a key using Argon2id version 0x13 (Argon2 v1.3) and returns exactly 32 bytes as 64 lowercase hexadecimal characters.

#### Scenario: Successful derivation
- **WHEN** valid hex password and salt and in-range parameters are provided
- **THEN** the function returns a deterministic 64-character lowercase hex string

#### Scenario: Fixed output length
- **WHEN** the function is invoked with any valid inputs
- **THEN** the derived key length is always 32 bytes (no caller-supplied output length)

#### Scenario: Password is opaque bytes
- **WHEN** the caller passes password material
- **THEN** the library treats it as hex-decoded bytes only and does not interpret JavaScript strings as UTF-8 passwords

### Requirement: Parameter validation
The library SHALL reject invalid inputs with a clear error and SHALL NOT silently clamp or adjust parameters.

#### Scenario: Password and salt hex bounds
- **WHEN** `passwordHex` or `saltHex` is odd-length, non-hex, or decodes outside password 0–1024 bytes or salt 8–64 bytes
- **THEN** the call fails with an error

#### Scenario: Cost parameter bounds
- **WHEN** parameters violate `8*p ≤ memoryKiB ≤ 65536`, `1 ≤ iterations ≤ 64`, or `1 ≤ parallelism ≤ 4`
- **THEN** the call fails with an error

#### Scenario: No forced m alignment reject
- **WHEN** `memoryKiB` is not a multiple of `4*parallelism` but otherwise in range
- **THEN** the call is not rejected solely for that reason (RFC rounding semantics apply inside the algorithm)

### Requirement: Wallet profile support
The library SHALL successfully compute Argon2id for the intended wallet profiles under the wasm memory policy cap.

#### Scenario: Wallet profiles
- **WHEN** parameters are `(19456,2,1)`, `(32768,3,1)`, or `(65536,3,1)` with a valid salt
- **THEN** derivation succeeds and returns 32 bytes

### Requirement: Runtime surfaces
The primitive SHALL be available on both package entry points without CDN loading or WASM threads.

#### Scenario: Node / bundler
- **WHEN** a consumer imports `crypto` from the main package entry
- **THEN** `crypto.argon2id` is available without a separate init call

#### Scenario: Browser after init
- **WHEN** a consumer uses the browser entry and has awaited `init()`
- **THEN** `crypto.argon2id` is available

### Requirement: Known-answer correctness
The implementation SHALL match independent Argon2id test vectors (RustCrypto-compatible, empty secret and associated data).

#### Scenario: Known-answer vector
- **WHEN** a published independent KAT is applied
- **THEN** the derived hex matches the expected tag

#### Scenario: Salt diversity
- **WHEN** the same password and costs are used with two different salts
- **THEN** the outputs differ
