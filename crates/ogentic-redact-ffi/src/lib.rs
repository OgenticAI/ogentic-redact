//! C ABI for safe one-way redaction and explicit store-backed reversible calls.
//! The built-in EMAIL/PHONE/US_SSN scanner is a development convenience.
//! Returned buffers belong to Rust and must be released with ogentic_redact_free.

use ogentic_redact_core::{
    MappingStore, RedactError, RedactMode, RestorationLimits, DEFAULT_MAX_OUTPUT_BYTES,
    DEFAULT_MAX_REPLACEMENTS,
};
use std::collections::HashMap;

unsafe fn bytes_to_str<'a>(ptr: *const u8, len: usize) -> Option<&'a str> {
    if len == 0 {
        return Some("");
    }
    if ptr.is_null() {
        return None;
    }
    std::str::from_utf8(unsafe { std::slice::from_raw_parts(ptr, len) }).ok()
}

fn vec_to_raw(v: Vec<u8>) -> (*mut u8, usize) {
    let bytes = v.into_boxed_slice();
    let len = bytes.len();
    (Box::into_raw(bytes) as *mut u8, len)
}

fn payload_to_raw(value: serde_json::Value, out_len: *mut usize) -> *mut u8 {
    if out_len.is_null() {
        return std::ptr::null_mut();
    }
    let bytes = match serde_json::to_vec(&value) {
        Ok(bytes) => bytes,
        Err(_) => return std::ptr::null_mut(),
    };
    let (ptr, len) = vec_to_raw(bytes);
    unsafe {
        *out_len = len;
    }
    ptr
}

/// Free a library buffer exactly once, using the returned length.
/// # Safety
/// `ptr` and `len` must match a live buffer returned by this library.
#[no_mangle]
pub unsafe extern "C" fn ogentic_redact_free(ptr: *mut u8, len: usize) {
    if !ptr.is_null() {
        let _ = unsafe { Box::from_raw(std::ptr::slice_from_raw_parts_mut(ptr, len)) };
    }
}

/// Static version string; do not free it.
#[no_mangle]
pub extern "C" fn ogentic_redact_version() -> *const std::os::raw::c_char {
    concat!(env!("CARGO_PKG_VERSION"), "\0").as_ptr().cast()
}

/// One-way JSON result: {"text": string, "redaction_count": integer}.
/// No original values or mapping are returned or retained.
/// # Safety
/// Non-null input must address input_len readable bytes; out_len must be writable.
#[no_mangle]
pub unsafe extern "C" fn ogentic_redact(
    input: *const u8,
    input_len: usize,
    out_len: *mut usize,
) -> *mut u8 {
    if out_len.is_null() {
        return std::ptr::null_mut();
    }
    unsafe {
        *out_len = 0;
    }
    let Some(text) = (unsafe { bytes_to_str(input, input_len) }) else {
        return std::ptr::null_mut();
    };
    let result = ogentic_redact_core::redact_one_way(text);
    payload_to_raw(
        serde_json::json!({"text": result.text, "redaction_count": result.redaction_count}),
        out_len,
    )
}

/// Deterministic one-way result with the same safe shape as ogentic_redact.
/// # Safety
/// Input/salt must address their given lengths; out_len must be writable.
#[no_mangle]
pub unsafe extern "C" fn ogentic_redact_with_salt(
    input: *const u8,
    input_len: usize,
    salt: *const u8,
    salt_len: usize,
    out_len: *mut usize,
) -> *mut u8 {
    if out_len.is_null() {
        return std::ptr::null_mut();
    }
    unsafe {
        *out_len = 0;
    }
    let Some(text) = (unsafe { bytes_to_str(input, input_len) }) else {
        return std::ptr::null_mut();
    };
    if salt.is_null() && salt_len != 0 {
        return std::ptr::null_mut();
    }
    let salt = if salt_len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(salt, salt_len) }
    };
    let result = ogentic_redact_core::redact_one_way_with_salt(text, salt);
    payload_to_raw(
        serde_json::json!({"text": result.text, "redaction_count": result.redaction_count}),
        out_len,
    )
}

fn restoration_status(error: &RedactError) -> u8 {
    match error {
        RedactError::UnknownMappingId { .. } => 1,
        RedactError::RestorationLimitExceeded => 2,
        RedactError::RestorationAllocationFailed => 4,
        _ => 3,
    }
}

unsafe fn set_status(out_status: *mut u8, value: u8) {
    if !out_status.is_null() {
        unsafe {
            *out_status = value;
        }
    }
}

/// Legacy explicit-map restoration using safe default resource limits.
/// # Safety
/// Input/map must address their lengths; out_len must be writable.
#[no_mangle]
pub unsafe extern "C" fn ogentic_unredact(
    input: *const u8,
    input_len: usize,
    token_map_json: *const u8,
    token_map_len: usize,
    out_len: *mut usize,
) -> *mut u8 {
    unsafe {
        ogentic_unredact_with_limits(
            input,
            input_len,
            token_map_json,
            token_map_len,
            DEFAULT_MAX_OUTPUT_BYTES,
            DEFAULT_MAX_REPLACEMENTS,
            out_len,
            std::ptr::null_mut(),
        )
    }
}

/// Explicit-map restoration with bounded output and mapped-token occurrences.
/// Optional status: 0 success, 1 missing mapping, 2 limit exceeded, 3 invalid
/// arguments, 4 allocation failed. Failure returns NULL and output length zero.
/// # Safety
/// Inputs must address their lengths; out_len and non-null out_status must be writable.
#[no_mangle]
pub unsafe extern "C" fn ogentic_unredact_with_limits(
    input: *const u8,
    input_len: usize,
    token_map_json: *const u8,
    token_map_len: usize,
    max_output_bytes: usize,
    max_replacements: usize,
    out_len: *mut usize,
    out_status: *mut u8,
) -> *mut u8 {
    unsafe {
        set_status(out_status, 3);
    }
    if out_len.is_null() {
        return std::ptr::null_mut();
    }
    unsafe {
        *out_len = 0;
    }
    let Some(text) = (unsafe { bytes_to_str(input, input_len) }) else {
        return std::ptr::null_mut();
    };
    let Some(map_json) = (unsafe { bytes_to_str(token_map_json, token_map_len) }) else {
        return std::ptr::null_mut();
    };
    let Ok(map) = serde_json::from_str::<HashMap<String, String>>(map_json) else {
        return std::ptr::null_mut();
    };
    let restored = match ogentic_redact_core::unredact_one_way_with_limits(
        text,
        &map,
        RestorationLimits {
            max_output_bytes,
            max_replacements,
        },
    ) {
        Ok(restored) => restored,
        Err(error) => {
            unsafe {
                set_status(out_status, restoration_status(&error));
            }
            return std::ptr::null_mut();
        },
    };
    let (ptr, len) = vec_to_raw(restored.into_bytes());
    unsafe {
        *out_len = len;
        set_status(out_status, 0);
    }
    ptr
}

/// Explicit opt-in reversible session; originals remain scoped to this handle.
pub struct OgenticRedactor {
    store: MappingStore,
    limits: RestorationLimits,
}

/// Create an in-process reversible mapping store. Close it when finished.
#[no_mangle]
pub extern "C" fn ogentic_redactor_open() -> *mut OgenticRedactor {
    ogentic_redactor_open_with_limits(DEFAULT_MAX_OUTPUT_BYTES, DEFAULT_MAX_REPLACEMENTS)
}

/// Create a reversible session with explicit restoration budgets; zero is valid.
#[no_mangle]
pub extern "C" fn ogentic_redactor_open_with_limits(
    max_output_bytes: usize,
    max_replacements: usize,
) -> *mut OgenticRedactor {
    Box::into_raw(Box::new(OgenticRedactor {
        store: MappingStore::new(),
        limits: RestorationLimits {
            max_output_bytes,
            max_replacements,
        },
    }))
}

/// Close a store and discard all retained mappings.
/// # Safety
/// Handle must be live and exclusively owned; no calls may race with close.
#[no_mangle]
pub unsafe extern "C" fn ogentic_redactor_close(handle: *mut OgenticRedactor) {
    if !handle.is_null() {
        let _ = unsafe { Box::from_raw(handle) };
    }
}

/// Reversible result: {"text": string, "mapping_id": opaque string}.
/// # Safety
/// Handle must be live; input must address its length; out_len must be writable.
#[no_mangle]
pub unsafe extern "C" fn ogentic_redactor_redact(
    handle: *mut OgenticRedactor,
    input: *const u8,
    input_len: usize,
    out_len: *mut usize,
) -> *mut u8 {
    if out_len.is_null() {
        return std::ptr::null_mut();
    }
    unsafe {
        *out_len = 0;
    }
    if handle.is_null() {
        return std::ptr::null_mut();
    }
    let Some(text) = (unsafe { bytes_to_str(input, input_len) }) else {
        return std::ptr::null_mut();
    };
    let store = &unsafe { &*handle }.store;
    let Ok((text, Some(mapping_id))) =
        ogentic_redact_core::redact(text, "default", RedactMode::Reversible, Some(store))
    else {
        return std::ptr::null_mut();
    };
    payload_to_raw(
        serde_json::json!({"text":text,"mapping_id":mapping_id}),
        out_len,
    )
}

/// Restore within this session's limits. Successful consume atomically deletes.
/// Failure (including a limit error) preserves the mapping and returns NULL.
/// # Safety
/// Handle must be live, byte inputs readable, and out_len writable.
#[no_mangle]
pub unsafe extern "C" fn ogentic_redactor_unredact(
    handle: *mut OgenticRedactor,
    input: *const u8,
    input_len: usize,
    mapping_id: *const u8,
    mapping_id_len: usize,
    consume: u8,
    out_len: *mut usize,
) -> *mut u8 {
    unsafe {
        ogentic_redactor_unredact_with_status(
            handle,
            input,
            input_len,
            mapping_id,
            mapping_id_len,
            consume,
            out_len,
            std::ptr::null_mut(),
        )
    }
}

/// Restore with an optional explicit status (same codes as ogentic_unredact_with_limits).
/// # Safety
/// Handle and byte inputs must be valid; out_len/non-null out_status must be writable.
#[no_mangle]
pub unsafe extern "C" fn ogentic_redactor_unredact_with_status(
    handle: *mut OgenticRedactor,
    input: *const u8,
    input_len: usize,
    mapping_id: *const u8,
    mapping_id_len: usize,
    consume: u8,
    out_len: *mut usize,
    out_status: *mut u8,
) -> *mut u8 {
    unsafe {
        set_status(out_status, 3);
    }
    if out_len.is_null() {
        return std::ptr::null_mut();
    }
    unsafe {
        *out_len = 0;
    }
    if handle.is_null() {
        return std::ptr::null_mut();
    }
    let Some(text) = (unsafe { bytes_to_str(input, input_len) }) else {
        return std::ptr::null_mut();
    };
    let Some(id) = (unsafe { bytes_to_str(mapping_id, mapping_id_len) }) else {
        return std::ptr::null_mut();
    };
    let session = unsafe { &*handle };
    let result = if consume != 0 {
        ogentic_redact_core::unredact_and_delete_with_limits(
            text,
            id,
            &session.store,
            session.limits,
        )
    } else {
        ogentic_redact_core::unredact_with_limits(text, id, &session.store, session.limits)
    };
    let restored = match result {
        Ok(restored) => restored,
        Err(error) => {
            unsafe {
                set_status(out_status, restoration_status(&error));
            }
            return std::ptr::null_mut();
        },
    };
    let (ptr, len) = vec_to_raw(restored.into_bytes());
    unsafe {
        *out_len = len;
        set_status(out_status, 0);
    }
    ptr
}

/// Delete a mapping, returning 1 if it existed or 0 otherwise.
/// # Safety
/// Handle must be live and mapping_id must address its length.
#[no_mangle]
pub unsafe extern "C" fn ogentic_redactor_delete(
    handle: *mut OgenticRedactor,
    mapping_id: *const u8,
    mapping_id_len: usize,
) -> u8 {
    if handle.is_null() {
        return 0;
    }
    let Some(id) = (unsafe { bytes_to_str(mapping_id, mapping_id_len) }) else {
        return 0;
    };
    u8::from(unsafe { &*handle }.store.delete(id))
}

/// Batch-redacted text delivered on demand as exact sentence slices.
/// Opening processes the complete document before any chunk is available.
pub struct OgenticRedactStream {
    text: String,
    offset: usize,
}

/// Redact the entire input once, then deliver sentence slices on demand.
/// This is batch processing, not incremental detection or a live input stream.
/// # Safety
/// Input must address input_len readable bytes (NULL is accepted for empty input).
#[no_mangle]
pub unsafe extern "C" fn ogentic_redact_stream_open(
    input: *const u8,
    input_len: usize,
) -> *mut OgenticRedactStream {
    let Some(text) = (unsafe { bytes_to_str(input, input_len) }) else {
        return std::ptr::null_mut();
    };
    let result = ogentic_redact_core::redact_one_way(text);
    Box::into_raw(Box::new(OgenticRedactStream {
        text: result.text,
        offset: 0,
    }))
}

/// Next JSON chunk {"text": string}; concatenation preserves every input separator.
/// No plaintext mappings are retained. NULL/length 0 means end of delivery.
/// # Safety
/// Handle must be live with exclusive access; out_len must be writable.
#[no_mangle]
pub unsafe extern "C" fn ogentic_redact_stream_next(
    handle: *mut OgenticRedactStream,
    out_len: *mut usize,
) -> *mut u8 {
    if out_len.is_null() {
        return std::ptr::null_mut();
    }
    unsafe {
        *out_len = 0;
    }
    if handle.is_null() {
        return std::ptr::null_mut();
    }
    let stream = unsafe { &mut *handle };
    if stream.offset >= stream.text.len() {
        return std::ptr::null_mut();
    }
    let remaining = &stream.text[stream.offset..];
    let length = remaining
        .char_indices()
        .find(|(_, c)| matches!(c, '.' | '!' | '?' | '\n'))
        .map_or(remaining.len(), |(i, c)| i + c.len_utf8());
    let payload = serde_json::json!({"text": &remaining[..length]});
    stream.offset += length;
    payload_to_raw(payload, out_len)
}

/// Close sentence delivery and release its redacted document.
/// # Safety
/// Handle must be live and exclusively owned; do not access after closing.
#[no_mangle]
pub unsafe extern "C" fn ogentic_redact_stream_close(handle: *mut OgenticRedactStream) {
    if !handle.is_null() {
        let _ = unsafe { Box::from_raw(handle) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    unsafe fn read_json(ptr: *mut u8, len: usize) -> serde_json::Value {
        assert!(!ptr.is_null());
        let value =
            serde_json::from_slice(unsafe { std::slice::from_raw_parts(ptr, len) }).unwrap();
        unsafe { ogentic_redact_free(ptr, len) };
        value
    }
    #[test]
    fn default_and_salted_results_do_not_expose_plaintext() {
        let text = "Email alice@example.com.";
        let mut n = 0;
        unsafe {
            let p = ogentic_redact(text.as_ptr(), text.len(), &mut n);
            let r = read_json(p, n);
            assert_eq!(r["redaction_count"], 1);
            assert!(r.get("tokens").is_none());
            assert!(!r.to_string().contains("alice@example.com"));
            let p =
                ogentic_redact_with_salt(text.as_ptr(), text.len(), std::ptr::null(), 0, &mut n);
            assert!(!read_json(p, n).to_string().contains("alice@example.com"));
        }
    }
    #[test]
    fn reversible_handle_isolated_and_consumed() {
        let text = "Email alice@example.com or call 555-867-5309.";
        unsafe {
            let first = ogentic_redactor_open();
            let other = ogentic_redactor_open();
            let mut n = 0;
            let p = ogentic_redactor_redact(first, text.as_ptr(), text.len(), &mut n);
            let result = read_json(p, n);
            assert!(result.get("tokens").is_none());
            assert!(!result.to_string().contains("alice@example.com"));
            let redacted = result["text"].as_str().unwrap();
            let id = result["mapping_id"].as_str().unwrap();
            assert!(ogentic_redactor_unredact(
                other,
                redacted.as_ptr(),
                redacted.len(),
                id.as_ptr(),
                id.len(),
                0,
                &mut n
            )
            .is_null());
            let p = ogentic_redactor_unredact(
                first,
                redacted.as_ptr(),
                redacted.len(),
                id.as_ptr(),
                id.len(),
                1,
                &mut n,
            );
            assert!(!p.is_null());
            assert_eq!(
                std::str::from_utf8(std::slice::from_raw_parts(p, n)).unwrap(),
                text
            );
            ogentic_redact_free(p, n);
            assert!(ogentic_redactor_unredact(
                first,
                redacted.as_ptr(),
                redacted.len(),
                id.as_ptr(),
                id.len(),
                0,
                &mut n
            )
            .is_null());
            ogentic_redactor_close(first);
            ogentic_redactor_close(other);
        }
    }
    #[test]
    fn batch_sentence_delivery_preserves_whitespace() {
        let text = "  First sentence.\n\n Second sentence! \n";
        unsafe {
            let h = ogentic_redact_stream_open(text.as_ptr(), text.len());
            let mut output = String::new();
            loop {
                let mut n = 0;
                let p = ogentic_redact_stream_next(h, &mut n);
                if p.is_null() {
                    break;
                }
                let result = read_json(p, n);
                assert!(result.get("tokens").is_none());
                output.push_str(result["text"].as_str().unwrap());
            }
            ogentic_redact_stream_close(h);
            assert_eq!(output, text);
        }
    }
    #[test]
    fn invalid_utf8_fails_and_empty_input_is_supported() {
        unsafe {
            let mut n = 99;
            assert!(ogentic_redact([255].as_ptr(), 1, &mut n).is_null());
            assert_eq!(n, 0);
            let p = ogentic_redact(std::ptr::null(), 0, &mut n);
            assert_eq!(read_json(p, n)["text"], "");
        }
    }
    #[test]
    fn explicit_limits_report_utf8_size_occurrence_and_argument_failures() {
        let token = "[Person_12345678]";
        let map = r#"{"[Person_12345678]":"é"}"#;
        unsafe {
            let mut n = 99;
            let mut status = 99;
            for (bytes, occurrences) in [(1, 1), (2, 0)] {
                let p = ogentic_unredact_with_limits(
                    token.as_ptr(),
                    token.len(),
                    map.as_ptr(),
                    map.len(),
                    bytes,
                    occurrences,
                    &mut n,
                    &mut status,
                );
                assert!(p.is_null());
                assert_eq!((n, status), (0, 2));
            }
            let p = ogentic_unredact_with_limits(
                token.as_ptr(),
                token.len(),
                map.as_ptr(),
                map.len(),
                2,
                1,
                &mut n,
                &mut status,
            );
            assert!(!p.is_null());
            assert_eq!((n, status), (2, 0));
            assert_eq!(std::slice::from_raw_parts(p, n), "é".as_bytes());
            ogentic_redact_free(p, n);
            assert!(ogentic_unredact_with_limits(
                [255].as_ptr(),
                1,
                map.as_ptr(),
                map.len(),
                2,
                1,
                &mut n,
                &mut status
            )
            .is_null());
            assert_eq!((n, status), (0, 3));
            let p = ogentic_unredact_with_limits(
                std::ptr::null(),
                0,
                b"{}".as_ptr(),
                2,
                0,
                0,
                &mut n,
                &mut status,
            );
            assert!(!p.is_null());
            assert_eq!((n, status), (0, 0));
            ogentic_redact_free(p, n);
        }
    }

    #[test]
    fn failed_consuming_restore_reports_limit_and_keeps_mapping() {
        let original = "alice@example.com";
        unsafe {
            let h = ogentic_redactor_open_with_limits(100, 1);
            let mut n = 0;
            let p = ogentic_redactor_redact(h, original.as_ptr(), original.len(), &mut n);
            let result = read_json(p, n);
            let text = result["text"].as_str().unwrap();
            let id = result["mapping_id"].as_str().unwrap();
            let repeated = text.repeat(2);
            let mut status = 99;
            let p = ogentic_redactor_unredact_with_status(
                h,
                repeated.as_ptr(),
                repeated.len(),
                id.as_ptr(),
                id.len(),
                1,
                &mut n,
                &mut status,
            );
            assert!(p.is_null());
            assert_eq!((n, status), (0, 2));
            let p = ogentic_redactor_unredact_with_status(
                h,
                text.as_ptr(),
                text.len(),
                id.as_ptr(),
                id.len(),
                1,
                &mut n,
                &mut status,
            );
            assert!(!p.is_null());
            assert_eq!(status, 0);
            assert_eq!(std::slice::from_raw_parts(p, n), original.as_bytes());
            ogentic_redact_free(p, n);
            assert!(ogentic_redactor_unredact_with_status(
                h,
                text.as_ptr(),
                text.len(),
                id.as_ptr(),
                id.len(),
                0,
                &mut n,
                &mut status
            )
            .is_null());
            assert_eq!((n, status), (0, 1));
            ogentic_redactor_close(h);
        }
    }
}
