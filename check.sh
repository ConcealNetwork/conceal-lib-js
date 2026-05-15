#!/usr/bin/env bash
set -euo pipefail

TARGET="wasm32-unknown-unknown"

fmt() {
    echo "==> rustfmt (check)"
    cargo fmt --all -- --check
}

lint() {
    echo "==> clippy"
    cargo clippy --workspace --target "$TARGET" -- -D warnings
}

case "${1:-all}" in
    fmt)  fmt ;;
    lint) lint ;;
    all)  fmt && lint ;;
    *)
        echo "Usage: $0 [fmt|lint|all]"
        exit 1
        ;;
esac

echo "==> All checks passed"
