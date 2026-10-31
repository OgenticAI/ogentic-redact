#!/usr/bin/env bash
# Validate linking and public APIs from an independent SwiftPM application.
# The Rust archive must already be built with build-swift-ffi.sh.
set -euo pipefail
REPO_ROOT=$(cd -- "$(dirname -- "$0")/.." && pwd)
CONSUMER_DIR=$(mktemp -d "${TMPDIR:-/tmp}/ogentic-redact-swift-consumer.XXXXXX")
trap 'rm -rf "$CONSUMER_DIR"' EXIT
mkdir -p "$CONSUMER_DIR/Sources/Consumer"
cat > "$CONSUMER_DIR/Package.swift" <<'SWIFT'
// swift-tools-version: 5.9
import Foundation
import PackageDescription
let package = Package(
    name: "Consumer",
    platforms: [.macOS(.v13)],
    dependencies: [.package(path: ProcessInfo.processInfo.environment["REDACT_SWIFT_PACKAGE"]!)],
    targets: [.executableTarget(name: "Consumer", dependencies: [
        .product(name: "OgenticRedact", package: "OgenticRedact")
    ])]
)
SWIFT
cat > "$CONSUMER_DIR/Sources/Consumer/main.swift" <<'SWIFT'
import OgenticRedact
let input = "Email alice@example.com; call 555-867-5309; SSN 123-45-6789."
let safe = try OgenticRedact.redact(input)
precondition(safe.redactionCount == 3)
for original in ["alice@example.com", "555-867-5309", "123-45-6789"] {
    precondition(!safe.text.contains(original))
}
let redactor = try ReversibleRedactor()
let reversible = try redactor.redact(input)
let restored = try redactor.unredact(reversible.text, mappingId: reversible.mappingId, consume: true)
precondition(restored == input)
print("External SwiftPM consumer privacy and round-trip checks passed")
SWIFT
export REDACT_SWIFT_PACKAGE="$REPO_ROOT/swift/OgenticRedact"
# Run from the consumer directory, so accidentally relative linker paths fail.
cd -- "$CONSUMER_DIR"
swift run Consumer
