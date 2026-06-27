// swift-tools-version: 5.9
// Package.swift — OgenticRedact Swift bindings skeleton
// Rust → C → Swift bridge stub; actual binding code lands in subsequent tickets.

import PackageDescription

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
        // C shim that wraps the Rust FFI surface.
        // The pre-built Rust dylib will be vendored under `Frameworks/`
        // once the core detection logic lands.
        .systemLibrary(
            name: "COgenticRedact",
            path: "Sources/COgenticRedact",
            pkgConfig: nil,
            providers: nil
        ),
        // Swift wrapper over the C shim.
        .target(
            name: "OgenticRedact",
            dependencies: ["COgenticRedact"],
            path: "Sources/OgenticRedact"
        ),
        .testTarget(
            name: "OgenticRedactTests",
            dependencies: ["OgenticRedact"],
            path: "Tests/OgenticRedactTests"
        ),
    ]
)
