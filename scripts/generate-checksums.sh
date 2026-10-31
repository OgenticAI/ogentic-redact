#!/usr/bin/env bash
# Generate a deterministic manifest without hashing the manifest itself.
set -euo pipefail
if [ "$#" -ne 1 ]; then
  echo "usage: $0 <artifact-directory>" >&2
  exit 2
fi
cd -- "$1"
if command -v sha256sum >/dev/null 2>&1; then
  HASHER=(sha256sum)
else
  HASHER=(shasum -a 256)
fi
MANIFEST_TMP=$(mktemp "${TMPDIR:-/tmp}/ogentic-redact-checksums.XXXXXX")
trap 'rm -f "$MANIFEST_TMP"' EXIT
while IFS= read -r -d '' artifact; do
  "${HASHER[@]}" "$artifact"
done < <(find . -type f ! -path './SHA256SUMS.txt' -print0 | LC_ALL=C sort -z) > "$MANIFEST_TMP"
mv -- "$MANIFEST_TMP" SHA256SUMS.txt
