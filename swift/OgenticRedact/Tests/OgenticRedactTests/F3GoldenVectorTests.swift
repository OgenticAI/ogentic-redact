import XCTest
@testable import OgenticRedact

final class F3GoldenVectorTests: XCTestCase {
    private let input = "Email alice@example.com. Call 555-867-5309. SSN 123-45-6789."

    func testOneWayRedactionHidesEveryDetectedValue() throws {
        for result in [try OgenticRedact.redact(input), try OgenticRedact.redact(input, salt: [1, 2, 3])] {
            XCTAssertEqual(result.redactionCount, 3)
            XCTAssertFalse(result.isClean)
            for secret in ["alice@example.com", "555-867-5309", "123-45-6789"] {
                XCTAssertFalse(result.text.contains(secret))
            }
        }
        XCTAssertEqual(try OgenticRedact.redact("").text, "")
        XCTAssertTrue(try OgenticRedact.redact("clean text").isClean)
    }

    func testReversibleIsolationConsumeAndDelete() throws {
        let first = try ReversibleRedactor()
        let other = try ReversibleRedactor()
        let result = try first.redact(input)
        for secret in ["alice@example.com", "555-867-5309", "123-45-6789"] {
            XCTAssertFalse(result.text.contains(secret))
        }
        XCTAssertThrowsError(try other.unredact(result.text, mappingId: result.mappingId))
        XCTAssertEqual(try first.unredact(result.text, mappingId: result.mappingId, consume: true), input)
        XCTAssertThrowsError(try first.unredact(result.text, mappingId: result.mappingId))
        let discarded = try first.redact(input)
        XCTAssertTrue(first.delete(mappingId: discarded.mappingId))
        XCTAssertFalse(first.delete(mappingId: discarded.mappingId))
        XCTAssertThrowsError(try first.unredact(discarded.text, mappingId: discarded.mappingId))
    }

    func testSentenceDeliveryPreservesWhitespace() async throws {
        let text = "  First sentence.\n\n Second sentence! \n"
        var output = ""
        for try await chunk in OgenticRedact.redactStream(text) { output += chunk.text }
        XCTAssertEqual(output, text)
    }

    func testSentenceDeliveryHidesPII() async throws {
        var output = ""
        for try await chunk in OgenticRedact.redactStream(input) { output += chunk.text }
        for secret in ["alice@example.com", "555-867-5309", "123-45-6789"] {
            XCTAssertFalse(output.contains(secret))
        }
    }

    func testCancelledSentenceDeliveryStops() async throws {
        let task = Task { () throws -> Bool in
            withUnsafeCurrentTask { $0?.cancel() }
            do {
                for try await _ in OgenticRedact.redactStream(input) { return false }
                return true
            } catch is CancellationError { return true }
        }
        let stopped = try await task.value
        XCTAssertTrue(stopped)
    }

    func testRestorationLimitsCountUTF8BytesAndRejectInvalidBudgets() throws {
        let token = "[Person_12345678]"
        let map = [token: "é"]
        XCTAssertEqual(try OgenticRedact.unredact(token, using: map, maxOutputBytes: 2, maxReplacements: 1), "é")
        for (bytes, count) in [(1, 1), (2, 0)] {
            XCTAssertThrowsError(try OgenticRedact.unredact(token, using: map, maxOutputBytes: bytes, maxReplacements: count)) {
                XCTAssertEqual($0 as? OgenticRedactError, .restorationLimitExceeded)
            }
        }
        XCTAssertEqual(try OgenticRedact.unredact("", using: [:], maxOutputBytes: 0, maxReplacements: 0), "")
        XCTAssertThrowsError(try ReversibleRedactor(maxOutputBytes: -1)) {
            XCTAssertEqual($0 as? OgenticRedactError, .invalidRestorationLimits)
        }
        XCTAssertThrowsError(try OgenticRedact.unredact(token, using: map, maxReplacements: -1)) {
            XCTAssertEqual($0 as? OgenticRedactError, .invalidRestorationLimits)
        }
    }

    func testRejectedConsumeRetainsMappingAndReportsLimitError() throws {
        let session = try ReversibleRedactor(maxOutputBytes: 100, maxReplacements: 1)
        let result = try session.redact("alice@example.com")
        XCTAssertThrowsError(try session.unredact(result.text + result.text, mappingId: result.mappingId, consume: true)) {
            XCTAssertEqual($0 as? OgenticRedactError, .restorationLimitExceeded)
        }
        XCTAssertEqual(try session.unredact(result.text, mappingId: result.mappingId, consume: true), "alice@example.com")
        XCTAssertThrowsError(try session.unredact(result.text, mappingId: result.mappingId)) {
            XCTAssertEqual($0 as? OgenticRedactError, .mappingNotFound)
        }
    }

    func testVersionNonEmpty() { XCTAssertFalse(OgenticRedact.version.isEmpty) }
}
