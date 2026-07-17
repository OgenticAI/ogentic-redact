#!/usr/bin/env bash
# build-swift-ffi.sh — build the Rust FFI static library and copy it to the
# Swift package's `lib/` directory so `swift build` / `swift test` can link.
#
# Usage:
#   scripts/build-swift-ffi.sh              # arm64-apple-darwin only (default)
#   scripts/build-swift-ffi.sh --universal  # arm64 + x86_64 fat binary
#
# After a successful run the following file will exist:
#   swift/OgenticRedact/lib/libogentic_redact_ffi.a
#
# Requirements: cargo, lipo (macOS).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CRATE="ogentic-redact-ffi"
OUT_DIR="$REPO_ROOT/swift/OgenticRedact/lib"

ARM64_TARGET="aarch64-apple-darwin"
X86_TARGET="x86_64-apple-darwin"

UNIVERSAL=false
for arg in "$@"; do
  [ "$arg" = "--universal" ] && UNIVERSAL=true
done

mkdir -p "$OUT_DIR"

echo "==> Building $CRATE for $ARM64_TARGET ..."
cargo build \
  --manifest-path "$REPO_ROOT/Cargo.toml" \
  --package "$CRATE" \
  --target "$ARM64_TARGET" \
  --release

ARM64_LIB="$REPO_ROOT/target/$ARM64_TARGET/release/libogentic_redact_ffi.a"

if $UNIVERSAL; then
  echo "==> Building $CRATE for $X86_TARGET ..."
  cargo build \
    --manifest-path "$REPO_ROOT/Cargo.toml" \
    --package "$CRATE" \
    --target "$X86_TARGET" \
    --release

  X86_LIB="$REPO_ROOT/target/$X86_TARGET/release/libogentic_redact_ffi.a"

  echo "==> Creating universal binary with lipo ..."
  lipo -create "$ARM64_LIB" "$X86_LIB" -output "$OUT_DIR/libogentic_redact_ffi.a"
else
  cp "$ARM64_LIB" "$OUT_DIR/libogentic_redact_ffi.a"
fi

echo "==> Library written to $OUT_DIR/libogentic_redact_ffi.a"
echo "==> Run: swift test --package-path swift/OgenticRedact"
