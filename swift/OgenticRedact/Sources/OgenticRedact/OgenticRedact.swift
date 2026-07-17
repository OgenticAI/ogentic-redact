/// OgenticRedact — Swift binding for the `ogentic-redact` Rust library.
///
/// Wraps the C FFI surface exposed by `ogentic_redact.h` / `libogentic_redact_ffi`
/// with idiomatic Swift types.  All on-device; no network calls in the default
/// path.
///
/// # Quick start
/// ```swift
/// let result = try OgenticRedact.redact("Email alice@example.com for details.")
/// print(result.text)          // "Email [EMAIL_1] for details."
/// print(result.tokenMap)      // ["[EMAIL_1]": "alice@example.com"]
///
/// let restored = try OgenticRedact.unredact(result.text, using: result.tokenMap)
/// print(restored)             // "Email alice@example.com for details."
///
/// // Streaming (Meeting Mode)
/// for try await chunk in OgenticRedact.redactStream(longTranscript) {
///     updateUI(chunk)
/// }
/// ```
import Foundation
import COgenticRedact

// ── Errors ────────────────────────────────────────────────────────────────────

/// Errors that can be thrown by `OgenticRedact` operations.
public enum OgenticRedactError: Error, Equatable {
    /// The library returned a null pointer, indicating invalid UTF-8 input or OOM.
    case libraryError
    /// The JSON payload returned by the library could not be decoded.
    case jsonDecodingError(String)
    /// The provided token map is not valid JSON.
    case invalidTokenMap
}

// ── Result types ──────────────────────────────────────────────────────────────

/// The result of a redaction operation.
public struct RedactedText: Sendable, Equatable {
    /// The input text with PII replaced by placeholder tokens (e.g. `[EMAIL_1]`).
    public let text: String

    /// Maps each placeholder to the original value it replaced.
    ///
    /// Example: `["[EMAIL_1]": "alice@example.com"]`
    ///
    /// Pass this to `OgenticRedact.unredact(_:using:)` to restore the
    /// original text.
    public let tokenMap: [String: String]

    /// `true` when no PII was found and `text` equals the original input.
    public var isClean: Bool { tokenMap.isEmpty }
}

// ── Chunk type for streaming ───────────────────────────────────────────────────

/// A single sentence-level chunk from a streaming redaction session.
public struct RedactedChunk: Sendable, Equatable {
    /// The redacted sentence text.
    public let text: String
    /// Tokens discovered in this chunk only.
    public let tokenMap: [String: String]
}

// ── Raw payload shape (matches ogentic_redact's JSON output) ──────────────────

private struct RawRedactPayload: Decodable {
    let text: String
    let tokens: [String: String]
}

// ── Library version ───────────────────────────────────────────────────────────

/// The version string reported by the underlying Rust library.
public var ogenticRedactVersion: String {
    String(cString: ogentic_redact_version())
}

// ── Main namespace ────────────────────────────────────────────────────────────

/// Namespace for the on-device redaction API.
public enum OgenticRedact {

    // ── Version ───────────────────────────────────────────────────────────────

    /// The version of the underlying `ogentic-redact-ffi` library.
    public static var version: String { ogenticRedactVersion }

    // ── Synchronous API ───────────────────────────────────────────────────────

    /// Redact PII in `text` and return the redacted form with its token map.
    ///
    /// - Parameter text: Plain UTF-8 text that may contain PII.
    /// - Returns: A ``RedactedText`` containing the scrubbed text and the
    ///   token map needed to restore the original.
    /// - Throws: ``OgenticRedactError`` on library error or JSON decode failure.
    public static func redact(_ text: String) throws -> RedactedText {
        try text.withUTF8Bytes { ptr, len in
            var outLen: Int = 0
            guard let raw = ogentic_redact(ptr, len, &outLen) else {
                throw OgenticRedactError.libraryError
            }
            defer { ogentic_redact_free(raw, outLen) }
            return try decodePayload(raw, length: outLen)
        }
    }

    /// Restore redacted placeholders in `text` using `tokenMap`.
    ///
    /// - Parameters:
    ///   - text: A previously redacted string containing placeholder tokens.
    ///   - tokenMap: The ``RedactedText/tokenMap`` returned by a prior
    ///     ``redact(_:)`` call.
    /// - Returns: The original text with all placeholders substituted back.
    /// - Throws: ``OgenticRedactError`` on library error or invalid map.
    public static func unredact(_ text: String, using tokenMap: [String: String]) throws -> String {
        let mapData: Data
        do {
            mapData = try JSONSerialization.data(withJSONObject: tokenMap)
        } catch {
            throw OgenticRedactError.invalidTokenMap
        }

        return try text.withUTF8Bytes { textPtr, textLen in
            try mapData.withUnsafeBytes { mapBuf in
                let mapPtr = mapBuf.bindMemory(to: UInt8.self).baseAddress!
                var outLen: Int = 0
                guard let raw = ogentic_unredact(textPtr, textLen, mapPtr, mapData.count, &outLen) else {
                    throw OgenticRedactError.libraryError
                }
                defer { ogentic_redact_free(raw, outLen) }
                guard let result = String(bytes: UnsafeBufferPointer(start: raw, count: outLen),
                                          encoding: .utf8) else {
                    throw OgenticRedactError.libraryError
                }
                return result
            }
        }
    }

    // ── Streaming API ─────────────────────────────────────────────────────────

    /// Redact `text` as an `AsyncStream` of sentence-level ``RedactedChunk``
    /// values, suitable for Meeting Mode's low-latency display.
    ///
    /// The stream yields one chunk per detected sentence boundary (`.`, `!`,
    /// `?`, or `\n`).  The first chunk is delivered as soon as the first
    /// sentence is processed, without waiting for the rest of the input.
    ///
    /// ```swift
    /// for try await chunk in OgenticRedact.redactStream(transcript) {
    ///     appendToTranscript(chunk.text)
    /// }
    /// ```
    ///
    /// - Parameter text: Input text to redact incrementally.
    /// - Returns: An `AsyncThrowingStream` of ``RedactedChunk`` values.
    public static func redactStream(_ text: String) -> AsyncThrowingStream<RedactedChunk, Error> {
        AsyncThrowingStream { continuation in
            // Open the stream handle on a background task so callers can
            // `await` the first chunk without blocking the calling actor.
            Task.detached {
                do {
                    try text.withUTF8Bytes { ptr, len in
                        guard let handle = ogentic_redact_stream_open(ptr, len) else {
                            throw OgenticRedactError.libraryError
                        }
                        defer { ogentic_redact_stream_close(handle) }

                        while true {
                            var chunkLen: Int = 0
                            guard let chunkPtr = ogentic_redact_stream_next(handle, &chunkLen) else {
                                break // stream exhausted
                            }
                            let chunk: RedactedChunk
                            do {
                                let payload = try decodePayload(chunkPtr, length: chunkLen)
                                chunk = RedactedChunk(text: payload.text, tokenMap: payload.tokenMap)
                            } catch {
                                ogentic_redact_free(chunkPtr, chunkLen)
                                throw error
                            }
                            ogentic_redact_free(chunkPtr, chunkLen)
                            continuation.yield(chunk)
                        }
                        continuation.finish()
                    }
                } catch {
                    continuation.finish(throwing: error)
                }
            }
        }
    }
}

// ── Private helpers ───────────────────────────────────────────────────────────

/// Decode the JSON payload returned by `ogentic_redact` / stream next.
private func decodePayload(_ ptr: UnsafeMutablePointer<UInt8>, length: Int) throws -> RedactedText {
    let data = Data(bytes: ptr, count: length)
    do {
        let raw = try JSONDecoder().decode(RawRedactPayload.self, from: data)
        return RedactedText(text: raw.text, tokenMap: raw.tokens)
    } catch {
        throw OgenticRedactError.jsonDecodingError(error.localizedDescription)
    }
}

extension String {
    /// Call `body` with a pointer to the string's UTF-8 bytes and their length.
    ///
    /// Uses `withUTF8` to avoid a copy when the string's storage is already
    /// contiguous UTF-8.
    func withUTF8Bytes<R>(_ body: (UnsafePointer<UInt8>, Int) throws -> R) rethrows -> R {
        var copy = self
        return try copy.withUTF8 { buf in
            try body(buf.baseAddress!, buf.count)
        }
    }
}
