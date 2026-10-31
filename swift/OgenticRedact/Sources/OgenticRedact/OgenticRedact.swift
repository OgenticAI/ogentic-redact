/// Safe one-way redaction with explicit instance-scoped reversible mode.
/// The built-in EMAIL/PHONE/US_SSN scanner is a development convenience.
import Foundation
import COgenticRedact

public enum OgenticRedactError: Error, Equatable {
    case libraryError
    case jsonDecodingError
    case mappingNotFound
    case invalidTokenMap
    case invalidRestorationLimits
    case restorationLimitExceeded
}

/// One-way result. Original values and mapping identifiers are never retained.
public struct RedactedText: Sendable, Equatable, Decodable {
    public let text: String
    public let redactionCount: Int
    public var isClean: Bool { redactionCount == 0 }
    private enum CodingKeys: String, CodingKey {
        case text
        case redactionCount = "redaction_count"
    }
}

/// A byte-preserving sentence slice of an already-redacted document.
public struct RedactedChunk: Sendable, Equatable, Decodable {
    public let text: String
}

public struct ReversibleText: Sendable, Equatable, Decodable {
    public let text: String
    public let mappingId: String
    private enum CodingKeys: String, CodingKey {
        case text
        case mappingId = "mapping_id"
    }
}

public var ogenticRedactVersion: String { String(cString: ogentic_redact_version()) }

public enum OgenticRedact {
    public static var version: String { ogenticRedactVersion }

    public static func redact(_ text: String) throws -> RedactedText {
        try text.withUTF8Bytes { ptr, len in
            var outLen = 0
            guard let raw = ogentic_redact(ptr, len, &outLen) else { throw OgenticRedactError.libraryError }
            defer { ogentic_redact_free(raw, outLen) }
            return try decode(raw, length: outLen)
        }
    }

    /// Deterministic one-way output; never contains original values.
    public static func redact(_ text: String, salt: [UInt8]) throws -> RedactedText {
        try text.withUTF8Bytes { ptr, len in
            var outLen = 0
            let raw = salt.withUnsafeBufferPointer {
                ogentic_redact_with_salt(ptr, len, $0.baseAddress, $0.count, &outLen)
            }
            guard let raw else { throw OgenticRedactError.libraryError }
            defer { ogentic_redact_free(raw, outLen) }
            return try decode(raw, length: outLen)
        }
    }

    /// Legacy explicit-map restoration. Prefer ReversibleRedactor for new code.
    /// Limits count restored UTF-8 bytes and mapped token occurrences; zero is valid.
    public static func unredact(_ text: String, using tokenMap: [String: String],
                                maxOutputBytes: Int = 16 * 1024 * 1024,
                                maxReplacements: Int = 100_000) throws -> String {
        guard maxOutputBytes >= 0, maxReplacements >= 0 else { throw OgenticRedactError.invalidRestorationLimits }
        let data = try JSONSerialization.data(withJSONObject: tokenMap)
        return try text.withUTF8Bytes { ptr, len in
            try data.withUnsafeBytes { map in
                var n = 0
                var status: UInt8 = 0
                guard let raw = ogentic_unredact_with_limits(ptr, len, map.bindMemory(to: UInt8.self).baseAddress,
                                                data.count, maxOutputBytes, maxReplacements, &n, &status)
                else { throw restorationError(status) }
                defer { ogentic_redact_free(raw, n) }
                return try decodeText(raw, length: n)
            }
        }
    }

    /// Redact the complete document, then deliver exact sentence slices on demand.
    /// Detection finishes before the first chunk; no producer queue is allocated.
    /// Cancellation is checked before and after the native batch and between
    /// deliveries. An in-flight native batch completes before cancellation takes
    /// effect; cancellation stops subsequent chunk delivery.
    public static func redactStream(_ text: String) -> AsyncThrowingStream<RedactedChunk, Error> {
        let state = SentenceDeliveryState(text)
        return AsyncThrowingStream(unfolding: { try await state.next() })
    }
}

/// Explicit opt-in reversible mode. Originals stay in this instance's Rust store.
/// Instances are independent; delete or consume mappings after their useful life.
public final class ReversibleRedactor: @unchecked Sendable {
    private let handle: OpaquePointer

    /// Failed restoration keeps its mapping, including when consume is requested.
    public init(maxOutputBytes: Int = 16 * 1024 * 1024, maxReplacements: Int = 100_000) throws {
        guard maxOutputBytes >= 0, maxReplacements >= 0 else { throw OgenticRedactError.invalidRestorationLimits }
        guard let handle = ogentic_redactor_open_with_limits(maxOutputBytes, maxReplacements)
        else { throw OgenticRedactError.libraryError }
        self.handle = handle
    }

    deinit { ogentic_redactor_close(handle) }

    public func redact(_ text: String) throws -> ReversibleText {
        try text.withUTF8Bytes { ptr, len in
            var n = 0
            guard let raw = ogentic_redactor_redact(handle, ptr, len, &n) else { throw OgenticRedactError.libraryError }
            defer { ogentic_redact_free(raw, n) }
            return try decode(raw, length: n)
        }
    }

    public func unredact(_ text: String, mappingId: String, consume: Bool = false) throws -> String {
        try text.withUTF8Bytes { ptr, len in
            try mappingId.withUTF8Bytes { id, idLen in
                var n = 0
                var status: UInt8 = 0
                guard let raw = ogentic_redactor_unredact_with_status(handle, ptr, len, id, idLen,
                                                                    consume ? 1 : 0, &n, &status)
                else { throw restorationError(status) }
                defer { ogentic_redact_free(raw, n) }
                return try decodeText(raw, length: n)
            }
        }
    }

    @discardableResult
    public func delete(mappingId: String) -> Bool {
        mappingId.withUTF8Bytes { ogentic_redactor_delete(handle, $0, $1) != 0 }
    }
}

/// Pull-based sentence delivery serializes handle use and releases it at EOF,
/// cancellation, error, or when the abandoned sequence is deallocated.
private actor SentenceDeliveryState {
    private var input: String?
    private var handle: OpaquePointer?

    init(_ text: String) { input = text }
    deinit { if let handle { ogentic_redact_stream_close(handle) } }

    private func close() {
        if let handle { ogentic_redact_stream_close(handle) }
        handle = nil
        input = nil
    }

    func next() throws -> RedactedChunk? {
        do {
            try Task.checkCancellation()
            if let text = input {
                handle = text.withUTF8Bytes { ogentic_redact_stream_open($0, $1) }
                input = nil
                guard handle != nil else { throw OgenticRedactError.libraryError }
            }
            try Task.checkCancellation()
            guard let handle else { return nil }
            var n = 0
            guard let raw = ogentic_redact_stream_next(handle, &n) else { close(); return nil }
            defer { ogentic_redact_free(raw, n) }
            return try decode(raw, length: n)
        } catch {
            close()
            throw error
        }
    }
}

private func restorationError(_ status: UInt8) -> OgenticRedactError {
    switch Int32(status) {
    case OGENTIC_RESTORE_MAPPING_NOT_FOUND: return .mappingNotFound
    case OGENTIC_RESTORE_LIMIT_EXCEEDED: return .restorationLimitExceeded
    case OGENTIC_RESTORE_INVALID_INPUT: return .invalidTokenMap
    default: return .libraryError
    }
}

private func decode<T: Decodable>(_ ptr: UnsafeMutablePointer<UInt8>, length: Int) throws -> T {
    do { return try JSONDecoder().decode(T.self, from: Data(bytes: ptr, count: length)) }
    catch { throw OgenticRedactError.jsonDecodingError }
}

private func decodeText(_ ptr: UnsafeMutablePointer<UInt8>, length: Int) throws -> String {
    guard let result = String(bytes: UnsafeBufferPointer(start: ptr, count: length), encoding: .utf8)
    else { throw OgenticRedactError.libraryError }
    return result
}

private extension String {
    func withUTF8Bytes<R>(_ body: (UnsafePointer<UInt8>, Int) throws -> R) rethrows -> R {
        // The trailing byte ensures a valid pointer even for empty strings.
        let bytes = Array(utf8) + [0]
        return try bytes.withUnsafeBufferPointer { try body($0.baseAddress!, $0.count - 1) }
    }
}
