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
    let call_salt_hex: String
    let vectors: [Vector]
}

private struct Vector: Decodable {
    let id: String
    let input: String
    let expected_text: String
    let expected_tokens: [String: String]
}

private func decodeHex(_ s: String) -> [UInt8] {
    var bytes: [UInt8] = []
    var idx = s.startIndex
    while idx < s.endIndex {
        let next = s.index(idx, offsetBy: 2)
        bytes.append(UInt8(s[idx..<next], radix: 16)!)
        idx = next
    }
    return bytes
}

// ── Test case ─────────────────────────────────────────────────────────────────

final class ConformanceVectorTests: XCTestCase {

    // MARK: - Helpers

    private func loadFile() throws -> VectorFile {
        guard let url = Bundle.module.url(forResource: "vectors", withExtension: "json") else {
            XCTFail("vectors.json not found in test bundle")
            return VectorFile(call_salt_hex: "", vectors: [])
        }
        let data = try Data(contentsOf: url)
        let file = try JSONDecoder().decode(VectorFile.self, from: data)
        XCTAssertFalse(file.vectors.isEmpty, "vectors.json must contain at least one vector")
        XCTAssertFalse(file.call_salt_hex.isEmpty, "vectors.json must carry a fixed call_salt_hex")
        return file
    }

    // MARK: - Conformance

    func testF4VectorsSwiftSurface() throws {
        let file = try loadFile()
        let salt = decodeHex(file.call_salt_hex)

        for v in file.vectors {
            let result = try OgenticRedact.redact(v.input, salt: salt)

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

            // Round-trip (ADR-0003 §9).
            let restored = try OgenticRedact.unredact(result.text, using: result.tokenMap)
            XCTAssertEqual(
                restored,
                v.input,
                "[\(v.id)] round-trip mismatch — input: \(v.input.debugDescription)"
            )
        }
    }
}
