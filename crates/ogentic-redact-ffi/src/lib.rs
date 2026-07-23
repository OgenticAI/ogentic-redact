//! `ogentic-redact-ffi` — C FFI shim for the `ogentic-redact` library.
//!
//! Exposes a stable C ABI so Swift (via `COgenticRedact`) and Tauri
//! (`src-tauri/src/redact.rs`) can call on-device redaction without a network
//! round-trip.
//!
//! # Stub notice
//!
//! The detection engine (REDACT-R6) has not landed yet.  This implementation
//! Detection routes through `ogentic-redact-core`; this crate is a thin C-ABI
//! shim that marshals bytes and JSON. The built-in byte-scanner is a documented
//! dev convenience (ADR-0002) — production spans come from Shield (OGE-1230).
//!
//! # Safety contract
//!
//! Every `*const u8` parameter that accompanies a `usize` length is treated as
//! a byte slice (`[u8; len]`).  Input strings must be valid UTF-8; the
//! functions return `null` / `{null, 0}` on any decoding error.
//!
//! Memory returned by the library is allocated on the Rust heap with the
//! global allocator.  Callers **must** free it via `ogentic_redact_free`.
//! Freeing with any other allocator (including Swift's / C's `free()`) is
//! undefined behaviour.

use std::collections::HashMap;

// ─── helpers ──────────────────────────────────────────────────────────────────

/// Convert a raw `(*const u8, usize)` pair to a `&str`.
/// Returns `None` when either the pointer is null or the bytes are not valid UTF-8.
unsafe fn bytes_to_str<'a>(ptr: *const u8, len: usize) -> Option<&'a str> {
    if ptr.is_null() {
        return None;
    }
    let slice = unsafe { std::slice::from_raw_parts(ptr, len) };
    std::str::from_utf8(slice).ok()
}

/// Move a `Vec<u8>` to the heap and hand ownership to the caller.
/// The returned `(ptr, len)` must be freed with `ogentic_redact_free`.
fn vec_to_raw(mut v: Vec<u8>) -> (*mut u8, usize) {
    v.shrink_to_fit();
    let len = v.len();
    let ptr = v.as_mut_ptr();
    std::mem::forget(v);
    (ptr, len)
}

// ─── public C API ─────────────────────────────────────────────────────────────

/// Free a buffer previously returned by `ogentic_redact` or `ogentic_unredact`.
///
/// # Safety
/// `ptr` must have been returned by this library and not yet freed.
#[no_mangle]
pub unsafe extern "C" fn ogentic_redact_free(ptr: *mut u8, len: usize) {
    if ptr.is_null() {
        return;
    }
    let _ = unsafe { Vec::from_raw_parts(ptr, len, len) };
}

/// Returns the library version as a null-terminated UTF-8 string.
/// The caller must **not** free the returned pointer — it is a static string.
#[no_mangle]
pub extern "C" fn ogentic_redact_version() -> *const std::os::raw::c_char {
    static VERSION: &std::ffi::CStr = match std::ffi::CStr::from_bytes_with_nul(
        concat!(env!("CARGO_PKG_VERSION"), "\0").as_bytes(),
    ) {
        Ok(s) => s,
        Err(_) => panic!("invalid version string"),
    };
    VERSION.as_ptr()
}

/// Serialise a [`RedactOneWayResult`] to the `{"text":…,"tokens":…}` JSON buffer
/// the C ABI returns, or `null` on serialisation failure.
fn result_to_raw(result: &ogentic_redact_core::RedactOneWayResult, out_len: *mut usize) -> *mut u8 {
    let payload = match serde_json::to_vec(&serde_json::json!({
        "text": result.text,
        "tokens": result.tokens,
    })) {
        Ok(v) => v,
        Err(_) => return std::ptr::null_mut(),
    };
    let len = payload.len();
    let (ptr, _) = vec_to_raw(payload);
    unsafe { *out_len = len };
    ptr
}

/// Redact PII in `input` (ADR-0003 grammar, `[Label_<salted-hex>]`).
///
/// Uses a fresh per-call salt, so the same value redacts differently across
/// calls. For reproducible output (e.g. conformance) use
/// [`ogentic_redact_with_salt`]. Detection routes through `ogentic-redact-core`.
///
/// Returns a heap-allocated JSON byte string of the form:
/// ```json
/// {"text":"…","tokens":{"[Email_3f8a2c1b]":"alice@example.com"}}
/// ```
/// Sets `*out_len` to the byte length of the returned buffer (NOT
/// null-terminated). Returns `null` on error (invalid UTF-8, OOM), with
/// `*out_len` set to `0`. The caller must free it with `ogentic_redact_free`.
///
/// # Safety
/// - `input` must point to `input_len` valid bytes.
/// - `out_len` must be a valid, non-null pointer.
#[no_mangle]
pub unsafe extern "C" fn ogentic_redact(
    input: *const u8,
    input_len: usize,
    out_len: *mut usize,
) -> *mut u8 {
    unsafe { *out_len = 0 };
    let text = match unsafe { bytes_to_str(input, input_len) } {
        Some(s) => s,
        None => return std::ptr::null_mut(),
    };
    result_to_raw(&ogentic_redact_core::redact_one_way(text), out_len)
}

/// [`ogentic_redact`] with an explicit `salt`, so output is reproducible.
///
/// All surfaces that share the fixed `salt` bytes produce byte-identical
/// output — this is how the F3 conformance vectors stay deterministic across
/// languages.
///
/// # Safety
/// - `input` must point to `input_len` valid bytes.
/// - `salt` must point to `salt_len` valid bytes (may be empty / any length).
/// - `out_len` must be a valid, non-null pointer.
#[no_mangle]
pub unsafe extern "C" fn ogentic_redact_with_salt(
    input: *const u8,
    input_len: usize,
    salt: *const u8,
    salt_len: usize,
    out_len: *mut usize,
) -> *mut u8 {
    unsafe { *out_len = 0 };
    let text = match unsafe { bytes_to_str(input, input_len) } {
        Some(s) => s,
        None => return std::ptr::null_mut(),
    };
    let salt_bytes: &[u8] = if salt.is_null() {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(salt, salt_len) }
    };
    result_to_raw(
        &ogentic_redact_core::redact_one_way_with_salt(text, salt_bytes),
        out_len,
    )
}

/// Restore redacted placeholders in `input` using `token_map_json`.
///
/// `token_map_json` must be a JSON object mapping placeholder strings to their
/// original values (i.e. the `"tokens"` field from `ogentic_redact`'s output).
///
/// Returns a heap-allocated UTF-8 byte buffer.  Sets `*out_len` to its length.
/// Returns `null` on error.
///
/// The caller must free the returned buffer with `ogentic_redact_free`.
///
/// # Safety
/// - `input` must point to `input_len` valid bytes.
/// - `token_map_json` must point to `token_map_len` valid bytes.
/// - `out_len` must be a valid, non-null pointer.
#[no_mangle]
pub unsafe extern "C" fn ogentic_unredact(
    input: *const u8,
    input_len: usize,
    token_map_json: *const u8,
    token_map_len: usize,
    out_len: *mut usize,
) -> *mut u8 {
    unsafe { *out_len = 0 };

    let text = match unsafe { bytes_to_str(input, input_len) } {
        Some(s) => s,
        None => return std::ptr::null_mut(),
    };
    let map_str = match unsafe { bytes_to_str(token_map_json, token_map_len) } {
        Some(s) => s,
        None => return std::ptr::null_mut(),
    };

    let map: HashMap<String, String> = match serde_json::from_str(map_str) {
        Ok(m) => m,
        Err(_) => return std::ptr::null_mut(),
    };

    // Scan-and-lookup via core (ADR-0003 §7), not a blind substring replace.
    let result = ogentic_redact_core::unredact_one_way(text, &map);

    let bytes = result.into_bytes();
    let len = bytes.len();
    let (ptr, _) = vec_to_raw(bytes);
    unsafe { *out_len = len };
    ptr
}

// ─── streaming API ────────────────────────────────────────────────────────────

/// Opaque streaming handle.
///
/// Created by `ogentic_redact_stream_open`, consumed chunk-by-chunk via
/// `ogentic_redact_stream_next`, and destroyed by `ogentic_redact_stream_close`.
///
/// The handle splits the input into sentence-level chunks (split on `.`, `!`,
/// `?`, or `\n`) and yields each redacted chunk in turn.  This gives Meeting
/// Mode a low-latency first-chunk while the rest is still being processed.
pub struct OgenticRedactStream {
    /// Pre-split chunks awaiting delivery.
    chunks: Vec<Vec<u8>>,
    /// Next index to yield.
    next: usize,
}

/// Open a streaming redaction session for `input`.
///
/// Returns an opaque `OgenticRedactStream *` or `null` on error (invalid
/// UTF-8, OOM).  Must be closed with `ogentic_redact_stream_close`.
///
/// # Safety
/// `input` must point to `input_len` valid bytes.
#[no_mangle]
pub unsafe extern "C" fn ogentic_redact_stream_open(
    input: *const u8,
    input_len: usize,
) -> *mut OgenticRedactStream {
    let text = match unsafe { bytes_to_str(input, input_len) } {
        Some(s) => s,
        None => return std::ptr::null_mut(),
    };

    // Redact the full text first so that sentence splitting does not fragment
    // PII tokens (e.g. splitting on the dot inside `alice@example.com`).
    let full = ogentic_redact_core::redact_one_way(text);
    let (redacted_full, all_tokens) = (full.text, full.tokens);

    // Split the *redacted* text on sentence-ending punctuation.
    let mut chunks: Vec<Vec<u8>> = Vec::new();
    let mut current = String::new();
    for ch in redacted_full.chars() {
        current.push(ch);
        if matches!(ch, '.' | '!' | '?' | '\n') {
            let sentence = current.trim().to_owned();
            if !sentence.is_empty() {
                // Only include tokens that appear in this sentence chunk.
                let relevant: HashMap<String, String> = all_tokens
                    .iter()
                    .filter(|(k, _)| sentence.contains(k.as_str()))
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect();
                let chunk = serde_json::to_vec(&serde_json::json!({
                    "text": sentence,
                    "tokens": relevant,
                }))
                .unwrap_or_default();
                if !chunk.is_empty() {
                    chunks.push(chunk);
                }
            }
            current.clear();
        }
    }
    // Trailing content without a sentence terminator
    let sentence = current.trim().to_owned();
    if !sentence.is_empty() {
        let relevant: HashMap<String, String> = all_tokens
            .iter()
            .filter(|(k, _)| sentence.contains(k.as_str()))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        let chunk = serde_json::to_vec(&serde_json::json!({
            "text": sentence,
            "tokens": relevant,
        }))
        .unwrap_or_default();
        if !chunk.is_empty() {
            chunks.push(chunk);
        }
    }

    let stream = Box::new(OgenticRedactStream { chunks, next: 0 });
    Box::into_raw(stream)
}

/// Yield the next redacted chunk from a streaming session.
///
/// Returns a heap-allocated buffer (same JSON format as `ogentic_redact`) and
/// sets `*out_len` to its byte length.  Returns `null` when the stream is
/// exhausted.  The returned buffer must be freed with `ogentic_redact_free`.
///
/// # Safety
/// - `handle` must be a valid pointer returned by `ogentic_redact_stream_open`.
/// - `out_len` must be a valid, non-null pointer.
#[no_mangle]
pub unsafe extern "C" fn ogentic_redact_stream_next(
    handle: *mut OgenticRedactStream,
    out_len: *mut usize,
) -> *mut u8 {
    unsafe { *out_len = 0 };

    if handle.is_null() {
        return std::ptr::null_mut();
    }
    let stream = unsafe { &mut *handle };
    if stream.next >= stream.chunks.len() {
        return std::ptr::null_mut();
    }

    let chunk = stream.chunks[stream.next].clone();
    stream.next += 1;

    let len = chunk.len();
    let (ptr, _) = vec_to_raw(chunk);
    unsafe { *out_len = len };
    ptr
}

/// Close and deallocate a streaming session.
///
/// # Safety
/// `handle` must be a valid pointer returned by `ogentic_redact_stream_open`.
/// After this call, the pointer is invalid.
#[no_mangle]
pub unsafe extern "C" fn ogentic_redact_stream_close(handle: *mut OgenticRedactStream) {
    if handle.is_null() {
        return;
    }
    let _ = unsafe { Box::from_raw(handle) };
}

// ─── tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Call the C ABI `ogentic_redact` and parse its JSON buffer.
    fn call_redact(text: &str) -> (String, HashMap<String, String>) {
        let mut out_len = 0usize;
        let ptr = unsafe { ogentic_redact(text.as_ptr(), text.len(), &mut out_len) };
        assert!(!ptr.is_null(), "ogentic_redact returned null");
        let bytes = unsafe { std::slice::from_raw_parts(ptr, out_len) };
        let json: serde_json::Value = serde_json::from_slice(bytes).unwrap();
        let out = json["text"].as_str().unwrap().to_owned();
        let tokens: HashMap<String, String> =
            serde_json::from_value(json["tokens"].clone()).unwrap();
        unsafe { ogentic_redact_free(ptr, out_len) };
        (out, tokens)
    }

    /// Call the C ABI `ogentic_unredact` and return the restored string.
    fn call_unredact(text: &str, tokens: &HashMap<String, String>) -> String {
        let map_json = serde_json::to_vec(tokens).unwrap();
        let mut out_len = 0usize;
        let ptr = unsafe {
            ogentic_unredact(
                text.as_ptr(),
                text.len(),
                map_json.as_ptr(),
                map_json.len(),
                &mut out_len,
            )
        };
        assert!(!ptr.is_null(), "ogentic_unredact returned null");
        let restored =
            String::from_utf8(unsafe { std::slice::from_raw_parts(ptr, out_len) }.to_vec())
                .unwrap();
        unsafe { ogentic_redact_free(ptr, out_len) };
        restored
    }

    #[test]
    fn c_abi_redact_emits_adr0003_grammar() {
        let (out, tokens) = call_redact("Contact alice@example.com for info.");
        assert!(!out.contains("alice@example.com"), "PII leaked: {out}");
        assert_eq!(tokens.len(), 1);
        let (tok, orig) = tokens.iter().next().unwrap();
        assert_eq!(orig, "alice@example.com");
        // New grammar: [Email_<8 lower-hex>].
        assert!(
            tok.starts_with("[Email_") && tok.ends_with(']'),
            "grammar: {tok}"
        );
        assert!(out.contains(tok));
    }

    #[test]
    fn c_abi_round_trip() {
        let original = "Email bob@acme.org for the invoice.";
        let (redacted, tokens) = call_redact(original);
        assert!(!redacted.contains("bob@acme.org"));
        assert_eq!(call_unredact(&redacted, &tokens), original);
    }

    #[test]
    fn c_abi_with_salt_is_reproducible() {
        // Same salt via the salted entry point → byte-identical output.
        let text = "ping a@b.com";
        let salt: [u8; 4] = [1, 2, 3, 4];
        let run = || {
            let mut n = 0usize;
            let p = unsafe {
                ogentic_redact_with_salt(
                    text.as_ptr(),
                    text.len(),
                    salt.as_ptr(),
                    salt.len(),
                    &mut n,
                )
            };
            let v = unsafe { std::slice::from_raw_parts(p, n) }.to_vec();
            unsafe { ogentic_redact_free(p, n) };
            String::from_utf8(v).unwrap()
        };
        assert_eq!(run(), run(), "same salt must give identical bytes");
    }

    #[test]
    fn c_abi_no_false_positives_on_plain_text() {
        let text = "The quick brown fox jumps over the lazy dog.";
        let (out, tokens) = call_redact(text);
        assert_eq!(out, text);
        assert!(tokens.is_empty());
    }
}
