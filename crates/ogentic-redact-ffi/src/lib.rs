//! `ogentic-redact-ffi` — C FFI shim for the `ogentic-redact` library.
//!
//! Exposes a stable C ABI so Swift (via `COgenticRedact`) and Tauri
//! (`src-tauri/src/redact.rs`) can call on-device redaction without a network
//! round-trip.
//!
//! # Stub notice
//!
//! The detection engine (REDACT-R6) has not landed yet.  This implementation
//! uses simple regex-free pattern matching (email, US-phone, SSN) as a
//! placeholder so the Swift binding and the F3 golden-vector tests can be
//! written and verified against a real, callable ABI.  Once REDACT-R6 ships,
//! the body of `redact_core` is replaced by a call into `ogentic-redact-core`
//! with no ABI change.
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

// ─── stub detection logic ─────────────────────────────────────────────────────

/// Scan `text` for recognisable PII patterns and replace each occurrence with
/// a placeholder token.  Returns `(redacted_text, token_map)`.
///
/// Patterns (stub, replaced by REDACT-R6 engine when it lands):
///   - Email: `word@word.tld`
///   - US phone: `(NXX) NXX-XXXX` and `NXX-NXX-XXXX` and `+1XXXXXXXXXX`
///   - SSN:   `DDD-DD-DDDD`
fn redact_core(text: &str) -> (String, HashMap<String, String>) {
    let mut out = String::with_capacity(text.len());
    let mut tokens: HashMap<String, String> = HashMap::new();
    let mut email_n = 0u32;
    let mut phone_n = 0u32;
    let mut ssn_n = 0u32;

    let bytes = text.as_bytes();
    let len = bytes.len();
    let mut i = 0;

    while i < len {
        // Try to match an email: word @ word . tld
        if let Some((email, end)) = try_match_email(bytes, i) {
            email_n += 1;
            let placeholder = format!("[EMAIL_{email_n}]");
            tokens.insert(placeholder.clone(), email);
            out.push_str(&placeholder);
            i = end;
            continue;
        }

        // Try to match an SSN before phone (SSN is digits-digits-digits)
        if let Some((ssn, end)) = try_match_ssn(bytes, i) {
            ssn_n += 1;
            let placeholder = format!("[SSN_{ssn_n}]");
            tokens.insert(placeholder.clone(), ssn);
            out.push_str(&placeholder);
            i = end;
            continue;
        }

        // Try to match a US phone number
        if let Some((phone, end)) = try_match_phone(bytes, i) {
            phone_n += 1;
            let placeholder = format!("[PHONE_{phone_n}]");
            tokens.insert(placeholder.clone(), phone);
            out.push_str(&placeholder);
            i = end;
            continue;
        }

        // Plain character — pass through
        // SAFETY: `bytes[i]` is a valid index; we reconstruct chars properly
        let ch = char::from(bytes[i]);
        if ch.is_ascii() {
            out.push(ch);
            i += 1;
        } else {
            // Decode a multi-byte UTF-8 sequence without indexing the middle bytes
            let tail = &text[i..];
            let c = tail.chars().next().unwrap();
            out.push(c);
            i += c.len_utf8();
        }
    }

    (out, tokens)
}

// ── pattern matchers (byte-level, no regex dependency) ────────────────────────

/// Match `word@word.tld` starting at `pos`.
/// Returns `(matched_str, end_pos)` or `None`.
fn try_match_email(b: &[u8], pos: usize) -> Option<(String, usize)> {
    // local-part: [a-zA-Z0-9._+-]+
    let mut i = pos;
    if i >= b.len() || !is_email_local(b[i]) {
        return None;
    }
    while i < b.len() && is_email_local(b[i]) {
        i += 1;
    }
    if i >= b.len() || b[i] != b'@' {
        return None;
    }
    let at = i;
    i += 1; // skip @
    // domain label
    if i >= b.len() || !b[i].is_ascii_alphanumeric() {
        return None;
    }
    while i < b.len() && (b[i].is_ascii_alphanumeric() || b[i] == b'.' || b[i] == b'-') {
        i += 1;
    }
    // Trim any trailing dots (e.g. `user@example.com.` at sentence end).
    // An email address cannot end with a dot.
    while i > at + 1 && b[i - 1] == b'.' {
        i -= 1;
    }
    // must have a dot somewhere after @
    let domain_slice = &b[at + 1..i];
    if !domain_slice.contains(&b'.') {
        return None;
    }
    // Ensure local-part started at a word boundary (not mid-word replacement)
    if pos > 0 && is_email_local(b[pos - 1]) {
        return None;
    }
    let matched = std::str::from_utf8(&b[pos..i]).ok()?.to_owned();
    Some((matched, i))
}

fn is_email_local(c: u8) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'+' | b'-')
}

/// Match SSN `DDD-DD-DDDD` starting at `pos`.
fn try_match_ssn(b: &[u8], pos: usize) -> Option<(String, usize)> {
    if pos + 11 > b.len() {
        return None;
    }
    // Boundary: not preceded by a digit
    if pos > 0 && b[pos - 1].is_ascii_digit() {
        return None;
    }
    let s = &b[pos..pos + 11];
    let ok = s[0].is_ascii_digit()
        && s[1].is_ascii_digit()
        && s[2].is_ascii_digit()
        && s[3] == b'-'
        && s[4].is_ascii_digit()
        && s[5].is_ascii_digit()
        && s[6] == b'-'
        && s[7].is_ascii_digit()
        && s[8].is_ascii_digit()
        && s[9].is_ascii_digit()
        && s[10].is_ascii_digit();
    if !ok {
        return None;
    }
    // Ensure not followed by a digit (e.g. SSN embedded in longer number)
    if pos + 11 < b.len() && b[pos + 11].is_ascii_digit() {
        return None;
    }
    let matched = std::str::from_utf8(s).ok()?.to_owned();
    Some((matched, pos + 11))
}

/// Match US phone starting at `pos`.  Formats supported:
///   `(NXX) NXX-XXXX`  →  16 chars
///   `NXX-NXX-XXXX`    →  12 chars
///   `+1-NXX-NXX-XXXX` →  15 chars
fn try_match_phone(b: &[u8], pos: usize) -> Option<(String, usize)> {
    // Boundary: not preceded by digit or letter
    if pos > 0 && (b[pos - 1].is_ascii_alphanumeric() || b[pos - 1] == b'.') {
        return None;
    }

    let rest = &b[pos..];

    // +1-NXX-NXX-XXXX
    if rest.starts_with(b"+1") && rest.len() >= 15 {
        let candidate = &rest[..15];
        if candidate[2] == b'-'
            && all_digits(&candidate[3..6])
            && candidate[6] == b'-'
            && all_digits(&candidate[7..10])
            && candidate[10] == b'-'
            && all_digits(&candidate[11..15])
        {
            let matched = std::str::from_utf8(candidate).ok()?.to_owned();
            return Some((matched, pos + 15));
        }
    }

    // (NXX) NXX-XXXX
    if rest.len() >= 14 && rest[0] == b'(' {
        let candidate = &rest[..14];
        if all_digits(&candidate[1..4])
            && candidate[4] == b')'
            && candidate[5] == b' '
            && all_digits(&candidate[6..9])
            && candidate[9] == b'-'
            && all_digits(&candidate[10..14])
        {
            let matched = std::str::from_utf8(candidate).ok()?.to_owned();
            return Some((matched, pos + 14));
        }
    }

    // NXX-NXX-XXXX
    if rest.len() >= 12 {
        let candidate = &rest[..12];
        if all_digits(&candidate[0..3])
            && candidate[3] == b'-'
            && all_digits(&candidate[4..7])
            && candidate[7] == b'-'
            && all_digits(&candidate[8..12])
        {
            // Boundary: not preceded by digit
            let matched = std::str::from_utf8(candidate).ok()?.to_owned();
            return Some((matched, pos + 12));
        }
    }

    None
}

fn all_digits(s: &[u8]) -> bool {
    s.iter().all(|b| b.is_ascii_digit())
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

/// Redact PII in `input`.
///
/// Returns a heap-allocated JSON byte string of the form:
/// ```json
/// {"text":"…","tokens":{"[EMAIL_1]":"alice@example.com"}}
/// ```
/// Sets `*out_len` to the byte length of the returned buffer (excluding any
/// null terminator — the buffer is NOT null-terminated).
///
/// Returns `null` on error (invalid UTF-8 input, OOM).  If `null` is returned,
/// `*out_len` is set to `0`.
///
/// The caller must free the returned buffer with `ogentic_redact_free`.
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

    let (redacted, tokens) = redact_core(text);

    let payload = match serde_json::to_vec(&serde_json::json!({
        "text": redacted,
        "tokens": tokens,
    })) {
        Ok(v) => v,
        Err(_) => return std::ptr::null_mut(),
    };

    let len = payload.len();
    let (ptr, _) = vec_to_raw(payload);
    unsafe { *out_len = len };
    ptr
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

    let mut result = text.to_owned();
    for (placeholder, original) in &map {
        result = result.replace(placeholder.as_str(), original.as_str());
    }

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
    let (redacted_full, all_tokens) = redact_core(text);

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

    #[test]
    fn email_detected() {
        let (out, tokens) = redact_core("Contact alice@example.com for info.");
        assert!(out.contains("[EMAIL_1]"), "email not redacted: {out}");
        assert_eq!(tokens.get("[EMAIL_1]").map(|s| s.as_str()), Some("alice@example.com"));
        assert!(!out.contains("alice@example.com"));
    }

    #[test]
    fn phone_dash_format() {
        let (out, tokens) = redact_core("Call 555-867-5309 now.");
        assert!(out.contains("[PHONE_1]"), "phone not redacted: {out}");
        assert_eq!(tokens.get("[PHONE_1]").map(|s| s.as_str()), Some("555-867-5309"));
    }

    #[test]
    fn phone_parens_format() {
        let (out, tokens) = redact_core("Reach me at (415) 555-0100.");
        assert!(out.contains("[PHONE_1]"), "phone not redacted: {out}");
        assert_eq!(tokens.get("[PHONE_1]").map(|s| s.as_str()), Some("(415) 555-0100"));
    }

    #[test]
    fn ssn_detected() {
        let (out, tokens) = redact_core("SSN: 123-45-6789.");
        assert!(out.contains("[SSN_1]"), "SSN not redacted: {out}");
        assert_eq!(tokens.get("[SSN_1]").map(|s| s.as_str()), Some("123-45-6789"));
    }

    #[test]
    fn unredact_round_trip() {
        let original = "Email bob@acme.org for the invoice.";
        let (redacted, tokens) = redact_core(original);
        assert!(!redacted.contains("bob@acme.org"));
        let mut restored = redacted.clone();
        for (k, v) in &tokens {
            restored = restored.replace(k.as_str(), v.as_str());
        }
        assert_eq!(restored, original);
    }

    #[test]
    fn no_false_positives_on_plain_text() {
        let text = "The quick brown fox jumps over the lazy dog.";
        let (out, tokens) = redact_core(text);
        assert_eq!(out, text);
        assert!(tokens.is_empty());
    }
}
