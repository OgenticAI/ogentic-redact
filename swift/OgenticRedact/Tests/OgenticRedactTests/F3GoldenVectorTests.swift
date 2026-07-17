/// F3 golden-vector test suite for the OgenticRedact Swift binding.
///
/// These tests verify that the Swift ↔ C ↔ Rust FFI bridge is wired correctly
/// and that the stub detection engine produces the expected output for the F3
/// baseline patterns (email, US phone, SSN).
///
/// Once REDACT-R6 (the full detection engine) lands, additional golden vectors
/// covering NER-based name/address/date detection will be added here.  The
/// existing vectors must continue to pass after REDACT-R6 is integrated.
///
/// ## Running
/// ```
/// scripts/build-swift-ffi.sh        # build libogentic_redact_ffi.a first
/// swift test --package-path swift/OgenticRedact
/// ```
import XCTest
@testable import OgenticRedact

// ── F3 vector catalogue ───────────────────────────────────────────────────────

/// A single F3 test vector.
private struct F3Vector {
    let name: String
    let input: String
    /// Expected placeholder key in the token map (e.g. `"[EMAIL_1]"`).
    let expectedToken: String
    /// The original value that should appear in the token map.
    let expectedOriginal: String
    /// Expected redacted text (the input with the original replaced by the token).
    let expectedText: String
}

// F3 baseline vectors — must all pass after REDACT-R6 integration.
private let f3Vectors: [F3Vector] = [
    // ── Email ──────────────────────────────────────────────────────────────
    F3Vector(
        name:             "email_simple",
        input:            "Contact alice@example.com for details.",
        expectedToken:    "[EMAIL_1]",
        expectedOriginal: "alice@example.com",
        expectedText:     "Contact [EMAIL_1] for details."
    ),
    F3Vector(
        name:             "email_with_subdomain",
        input:            "Forward to bob.smith@mail.corp.io now.",
        expectedToken:    "[EMAIL_1]",
        expectedOriginal: "bob.smith@mail.corp.io",
        expectedText:     "Forward to [EMAIL_1] now."
    ),
    F3Vector(
        name:             "email_with_plus_tag",
        input:            "Reply to carol+tag@example.org.",
        expectedToken:    "[EMAIL_1]",
        expectedOriginal: "carol+tag@example.org",
        expectedText:     "Reply to [EMAIL_1]."
    ),
    // ── US Phone — dash format ─────────────────────────────────────────────
    F3Vector(
        name:             "phone_dash_format",
        input:            "Call 555-867-5309 for support.",
        expectedToken:    "[PHONE_1]",
        expectedOriginal: "555-867-5309",
        expectedText:     "Call [PHONE_1] for support."
    ),
    // ── US Phone — parenthesis format ─────────────────────────────────────
    F3Vector(
        name:             "phone_parens_format",
        input:            "Office: (415) 555-0100.",
        expectedToken:    "[PHONE_1]",
        expectedOriginal: "(415) 555-0100",
        expectedText:     "Office: [PHONE_1]."
    ),
    // ── US Phone — E.164 format ───────────────────────────────────────────
    F3Vector(
        name:             "phone_e164_format",
        input:            "Text +1-800-555-0199 anytime.",
        expectedToken:    "[PHONE_1]",
        expectedOriginal: "+1-800-555-0199",
        expectedText:     "Text [PHONE_1] anytime."
    ),
    // ── SSN ────────────────────────────────────────────────────────────────
    F3Vector(
        name:             "ssn_basic",
        input:            "Patient SSN is 123-45-6789.",
        expectedToken:    "[SSN_1]",
        expectedOriginal: "123-45-6789",
        expectedText:     "Patient SSN is [SSN_1]."
    ),
]

// ── Test case ─────────────────────────────────────────────────────────────────

final class F3GoldenVectorTests: XCTestCase {

    // ── Vector-driven redaction tests ─────────────────────────────────────────

    func testF3VectorsRedact() throws {
        for vector in f3Vectors {
            let result = try OgenticRedact.redact(vector.input)
            XCTAssertEqual(
                result.text,
                vector.expectedText,
                "[\(vector.name)] redacted text mismatch"
            )
            XCTAssertEqual(
                result.tokenMap[vector.expectedToken],
                vector.expectedOriginal,
                "[\(vector.name)] token map entry mismatch"
            )
            XCTAssertFalse(
                result.text.contains(vector.expectedOriginal),
                "[\(vector.name)] original value still present in redacted text"
            )
        }
    }

    // ── Round-trip: redact → unredact ─────────────────────────────────────────

    func testF3VectorsRoundTrip() throws {
        for vector in f3Vectors {
            let redacted  = try OgenticRedact.redact(vector.input)
            let restored  = try OgenticRedact.unredact(redacted.text, using: redacted.tokenMap)
            XCTAssertEqual(
                restored,
                vector.input,
                "[\(vector.name)] round-trip failed: restored != original"
            )
        }
    }

    // ── Clean text (no PII) ───────────────────────────────────────────────────

    func testCleanTextPassthrough() throws {
        let clean = "The quick brown fox jumps over the lazy dog."
        let result = try OgenticRedact.redact(clean)
        XCTAssertEqual(result.text, clean, "clean text must not be modified")
        XCTAssertTrue(result.isClean, "isClean must be true for text with no PII")
        XCTAssertTrue(result.tokenMap.isEmpty)
    }

    // ── Multiple PII entities in one string ───────────────────────────────────

    func testMultipleEntities() throws {
        let input  = "Email alice@example.com or call 555-867-5309."
        let result = try OgenticRedact.redact(input)
        XCTAssertEqual(result.tokenMap.count, 2, "expected 2 tokens (email + phone)")
        XCTAssertFalse(result.text.contains("alice@example.com"))
        XCTAssertFalse(result.text.contains("555-867-5309"))
    }

    // ── Version query ─────────────────────────────────────────────────────────

    func testVersionNonEmpty() {
        let v = OgenticRedact.version
        XCTAssertFalse(v.isEmpty, "version string must not be empty")
    }

    // ── Streaming: chunk count matches sentence count ─────────────────────────

    func testRedactStreamChunks() async throws {
        let input = "Hello alice@example.com. Call 555-867-5309 tomorrow. Thanks!"
        var chunks: [RedactedChunk] = []
        for try await chunk in OgenticRedact.redactStream(input) {
            chunks.append(chunk)
        }
        XCTAssertEqual(chunks.count, 3, "expected 3 chunks (one per sentence)")

        // First chunk must have the email redacted
        XCTAssertTrue(
            chunks[0].tokenMap.values.contains("alice@example.com"),
            "first chunk must contain email token"
        )
        // Second chunk must have the phone redacted
        XCTAssertTrue(
            chunks[1].tokenMap.values.contains("555-867-5309"),
            "second chunk must contain phone token"
        )
    }

    // ── Streaming: single-sentence input yields one chunk ─────────────────────

    func testRedactStreamSingleChunk() async throws {
        let input = "SSN 123-45-6789 on file"
        var chunks: [RedactedChunk] = []
        for try await chunk in OgenticRedact.redactStream(input) {
            chunks.append(chunk)
        }
        // No sentence terminator → one trailing chunk
        XCTAssertEqual(chunks.count, 1)
        XCTAssertTrue(chunks[0].tokenMap.values.contains("123-45-6789"))
    }

    // ── Streaming: unredact using accumulated token map ───────────────────────

    func testRedactStreamUnredact() async throws {
        let input = "Email alice@example.com. Call 555-867-5309."
        var accumulated: [String: String] = [:]
        var redactedText = ""
        for try await chunk in OgenticRedact.redactStream(input) {
            redactedText += chunk.text + " "
            accumulated.merge(chunk.tokenMap) { _, new in new }
        }
        let restored = try OgenticRedact.unredact(redactedText.trimmingCharacters(in: .whitespaces),
                                                   using: accumulated)
        XCTAssertTrue(restored.contains("alice@example.com"))
        XCTAssertTrue(restored.contains("555-867-5309"))
    }
}
