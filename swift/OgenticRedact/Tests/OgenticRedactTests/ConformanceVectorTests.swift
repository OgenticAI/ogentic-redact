/// F3 cross-language conformance test — Swift surface.
///
/// Loads `Resources/vectors.json` (bundled via Package.swift `resources`)
/// and verifies that `OgenticRedact.redact(_:)` produces byte-identical
/// `text` and `tokens` output to the expected values.  Any divergence is an
/// XCTest failure (→ CI red).
///
/// Run (after `scripts/build-swift-ffi.sh`):
///   swift test --package-path swift/OgenticRedact --filter ConformanceVectorTests
import XCTest
@testable import OgenticRedact

// ── JSON model ────────────────────────────────────────────────────────────────

private struct VectorFile: Decodable {
    let vectors: [Vector]
}

private struct Vector: Decodable {
    let id: String
    let input: String
    let expected_text: String
    let expected_tokens: [String: String]
}

// ── Test case ─────────────────────────────────────────────────────────────────

final class ConformanceVectorTests: XCTestCase {

    // MARK: - Helpers

    private func loadVectors() throws -> [Vector] {
        guard let url = Bundle.module.url(forResource: "vectors", withExtension: "json") else {
            XCTFail("vectors.json not found in test bundle")
            return []
        }
        let data = try Data(contentsOf: url)
        let file = try JSONDecoder().decode(VectorFile.self, from: data)
        XCTAssertFalse(file.vectors.isEmpty, "vectors.json must contain at least one vector")
        return file.vectors
    }

    // MARK: - Conformance

    func testF3VectorsSwiftSurface() throws {
        let vectors = try loadVectors()

        for v in vectors {
            let result = try OgenticRedact.redact(v.input)

            XCTAssertEqual(
                result.text,
                v.expected_text,
                "[\(v.id)] text mismatch — input: \(v.input.debugDescription)"
            )
            XCTAssertEqual(
                result.tokenMap,
                v.expected_tokens,
                "[\(v.id)] tokens mismatch — input: \(v.input.debugDescription)"
            )
        }
    }
}
