/**
 * ogentic_redact.h — stable C ABI for the ogentic-redact-ffi library.
 *
 * This header is the boundary between `ogentic-redact-ffi` (a Rust crate
 * compiled to a static library) and the Swift `OgenticRedact` package.
 * It is regenerated from the Rust source via `cbindgen` and then checked in
 * so the Swift package can compile without a local Rust build.
 *
 * Run `scripts/build-swift-ffi.sh` to rebuild both the static library and
 * this header from source.
 *
 * ABI STABILITY GUARANTEE
 * -----------------------
 * The function signatures and struct layouts below are stable.  New
 * functionality is added in new functions; existing signatures are never
 * changed in a breaking way without a major version bump.
 *
 * MEMORY OWNERSHIP
 * ----------------
 * Every pointer returned by this library was allocated on the Rust heap.
 * Callers MUST free it with `ogentic_redact_free` — NOT with `free()` or
 * Swift's / C's allocators.  Double-free and use-after-free are undefined
 * behaviour.  A `null` return always means an error occurred; `*out_len` is
 * set to `0` in that case.
 */

#ifndef OGENTIC_REDACT_H
#define OGENTIC_REDACT_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── version ──────────────────────────────────────────────────────────────── */

/**
 * Returns the library version as a null-terminated UTF-8 string.
 *
 * The caller MUST NOT free the returned pointer — it points to a static
 * string owned by the Rust runtime.
 */
const char *ogentic_redact_version(void);

/* ── memory ───────────────────────────────────────────────────────────────── */

/**
 * Free a buffer previously returned by `ogentic_redact` or
 * `ogentic_unredact` or `ogentic_redact_stream_next`.
 *
 * @param ptr  Pointer returned by the library.  Ignored if NULL.
 * @param len  Byte length as reported by the corresponding `*out_len`.
 */
void ogentic_redact_free(uint8_t *ptr, size_t len);

/* ── synchronous API ──────────────────────────────────────────────────────── */

/**
 * Redact PII in `input` (ADR-0003 grammar).
 *
 * Scans `input` for recognisable PII patterns (email, US phone, SSN) and
 * replaces each with a salted placeholder token such as `[Email_3f8a2c1b]`.
 * A fresh per-call salt is used, so the same value redacts differently across
 * calls; use `ogentic_redact_with_salt` for reproducible output.
 *
 * Returns a heap-allocated JSON byte buffer of the form:
 * ```json
 * {
 *   "text":   "Contact [Email_3f8a2c1b] for info.",
 *   "tokens": { "[Email_3f8a2c1b]": "alice@example.com" }
 * }
 * ```
 * Sets `*out_len` to the byte length of the buffer (it is NOT
 * null-terminated).  Returns NULL on error (invalid UTF-8, OOM).
 *
 * The caller must free the returned buffer with `ogentic_redact_free`.
 *
 * No network calls are made.
 *
 * @param input      Pointer to UTF-8 encoded input bytes.
 * @param input_len  Length of `input` in bytes.
 * @param out_len    Set to the byte length of the returned buffer on success,
 *                   0 on error.
 * @return           Heap-allocated buffer, or NULL on error.
 */
uint8_t *ogentic_redact(const uint8_t *input,
                         size_t         input_len,
                         size_t        *out_len);

/**
 * Redact PII in `input` using an explicit `salt`, so the salted-hex tokens are
 * reproducible. Surfaces that share the same `salt` bytes produce byte-identical
 * output — this is how the cross-language conformance vectors stay deterministic.
 *
 * Same return contract and memory ownership as `ogentic_redact`.
 *
 * @param input      Pointer to UTF-8 encoded input bytes.
 * @param input_len  Length of `input` in bytes.
 * @param salt       Pointer to salt bytes (may be NULL/empty; any length).
 * @param salt_len   Length of `salt` in bytes.
 * @param out_len    Set to the byte length of the returned buffer, 0 on error.
 * @return           Heap-allocated buffer, or NULL on error.
 */
uint8_t *ogentic_redact_with_salt(const uint8_t *input,
                                   size_t         input_len,
                                   const uint8_t *salt,
                                   size_t         salt_len,
                                   size_t        *out_len);

/**
 * Restore redacted placeholders in `input`.
 *
 * `token_map_json` must be the JSON object from the `"tokens"` field of a
 * previous `ogentic_redact` call, mapping placeholder strings to their
 * original values.
 *
 * Returns a heap-allocated UTF-8 buffer containing the restored text.
 * Sets `*out_len` to its byte length.  Returns NULL on error.
 *
 * The caller must free the returned buffer with `ogentic_redact_free`.
 *
 * @param input              Redacted UTF-8 text.
 * @param input_len          Length of `input` in bytes.
 * @param token_map_json     JSON object (`{"[EMAIL_1]": "alice@…"}`).
 * @param token_map_len      Length of `token_map_json` in bytes.
 * @param out_len            Set to byte length of the restored buffer.
 * @return                   Heap-allocated restored text, or NULL on error.
 */
uint8_t *ogentic_unredact(const uint8_t *input,
                            size_t         input_len,
                            const uint8_t *token_map_json,
                            size_t         token_map_len,
                            size_t        *out_len);

/* ── streaming API ────────────────────────────────────────────────────────── */

/**
 * Opaque streaming handle created by `ogentic_redact_stream_open`.
 *
 * The handle internally splits the input into sentence-level chunks and
 * yields each chunk's redacted JSON in turn.  This gives Meeting Mode a
 * low-latency first result while subsequent sentences are still being
 * processed.
 */
typedef struct OgenticRedactStream OgenticRedactStream;

/**
 * Open a streaming redaction session for `input`.
 *
 * Splits the input on sentence-ending punctuation (`.`, `!`, `?`, `\n`),
 * redacts each chunk, and stores the results for delivery via
 * `ogentic_redact_stream_next`.
 *
 * Returns an opaque handle, or NULL on error (invalid UTF-8, OOM).
 * The caller must close the handle with `ogentic_redact_stream_close`
 * regardless of how many chunks were consumed.
 *
 * No network calls are made.
 *
 * @param input      Pointer to UTF-8 encoded input bytes.
 * @param input_len  Length of `input` in bytes.
 * @return           Opaque stream handle, or NULL on error.
 */
OgenticRedactStream *ogentic_redact_stream_open(const uint8_t *input,
                                                  size_t         input_len);

/**
 * Yield the next redacted chunk from a streaming session.
 *
 * Returns a heap-allocated JSON buffer in the same format as `ogentic_redact`
 * and sets `*out_len` to its byte length.  Returns NULL when the stream is
 * exhausted (i.e. all chunks have been delivered); `*out_len` is set to 0.
 *
 * The returned buffer must be freed with `ogentic_redact_free` before
 * calling `ogentic_redact_stream_next` again.
 *
 * @param handle   Valid handle from `ogentic_redact_stream_open`.  NULL is safe.
 * @param out_len  Set to byte length of the chunk on success, 0 when exhausted.
 * @return         Heap-allocated chunk buffer, or NULL when exhausted.
 */
uint8_t *ogentic_redact_stream_next(OgenticRedactStream *handle,
                                     size_t              *out_len);

/**
 * Close and deallocate a streaming session.
 *
 * Must be called exactly once per handle returned by
 * `ogentic_redact_stream_open`, even if the stream was not fully consumed.
 * After this call the handle pointer is invalid.
 *
 * @param handle  Handle to close.  NULL is safe (no-op).
 */
void ogentic_redact_stream_close(OgenticRedactStream *handle);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* OGENTIC_REDACT_H */
