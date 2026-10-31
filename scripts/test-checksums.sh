#!/usr/bin/env bash
# Check real verifier interoperability, repeatability, and tamper detection.
set -euo pipefail
SCRIPT_DIR=$(cd -- "$(dirname -- "$0")" && pwd)
TEST_DIR=$(mktemp -d "${TMPDIR:-/tmp}/ogentic-redact-checksum-test.XXXXXX")
trap 'rm -rf "$TEST_DIR"' EXIT
mkdir -p "$TEST_DIR/artifacts/nested"
printf 'first artifact\n' > "$TEST_DIR/artifacts/first.bin"
printf 'second artifact\n' > "$TEST_DIR/artifacts/nested/space name.bin"
printf 'obsolete manifest\n' > "$TEST_DIR/artifacts/SHA256SUMS.txt"
bash "$SCRIPT_DIR/generate-checksums.sh" "$TEST_DIR/artifacts"
cp "$TEST_DIR/artifacts/SHA256SUMS.txt" "$TEST_DIR/first-manifest"
bash "$SCRIPT_DIR/generate-checksums.sh" "$TEST_DIR/artifacts"
cmp "$TEST_DIR/first-manifest" "$TEST_DIR/artifacts/SHA256SUMS.txt"
cd -- "$TEST_DIR/artifacts"
if command -v sha256sum >/dev/null 2>&1; then
  HASHER=(sha256sum)
else
  HASHER=(shasum -a 256)
fi
"${HASHER[@]}" -c SHA256SUMS.txt
printf 'tampered\n' >> first.bin
if "${HASHER[@]}" -c SHA256SUMS.txt >/dev/null 2>&1; then
  echo 'tampered artifact unexpectedly passed checksum verification' >&2
  exit 1
fi
echo 'Checksum generation and tamper detection passed'
