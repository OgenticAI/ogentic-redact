// swift-tools-version: 5.9
// Package.swift — OgenticRedact Swift bindings
//
// The Rust static library `libogentic_redact_ffi.a` must be built before
// running `swift build` or `swift test`.  Use the helper script:
//
//   scripts/build-swift-ffi.sh
//
// That script compiles `crates/ogentic-redact-ffi` for `aarch64-apple-darwin`
// (and optionally `x86_64-apple-darwin`) and places the resulting `.a` under
// `swift/OgenticRedact/lib/`.

import PackageDescription

let libDir = "lib"   // relative to Package.swift — i.e. swift/OgenticRedact/lib/

let package = Package(
    name: "OgenticRedact",
    platforms: [
        .macOS(.v13),
        .iOS(.v16),
    ],
    products: [
        .library(
            name: "OgenticRedact",
            targets: ["OgenticRedact"]
        ),
    ],
    targets: [
        // C shim target — maps ogentic_redact.h into a Swift-importable module.
        // `libogentic_redact_ffi.a` is linked via the Swift target's linkerSettings.
        .target(
            name: "COgenticRedact",
            path: "Sources/COgenticRedact",
            publicHeadersPath: "."
        ),

        // Swift wrapper over the C shim.
        .target(
            name: "OgenticRedact",
            dependencies: ["COgenticRedact"],
            path: "Sources/OgenticRedact",
            linkerSettings: [
                // Link against the pre-built Rust static library.
                // Build it first with `scripts/build-swift-ffi.sh`.
                .linkedLibrary("ogentic_redact_ffi"),
                .unsafeFlags(["-L", "\(libDir)"]),
                // `libresolv` is required by Rust's standard library on macOS.
                .linkedLibrary("resolv"),
            ]
        ),

        // Test target — requires `libogentic_redact_ffi.a` to be present.
        .testTarget(
            name: "OgenticRedactTests",
            dependencies: ["OgenticRedact"],
            path: "Tests/OgenticRedactTests"
        ),
    ]
)
