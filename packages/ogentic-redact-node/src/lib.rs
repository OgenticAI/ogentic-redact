//! napi-rs binding for `ogentic-redact`.
//!
//! Exposes `version()`, `redact(text)`, and `unredact(text, tokens)` to Node.js.
//! The `redact` output is byte-identical to the Python and Swift bindings for
//! the same input — all three delegate to `ogentic-redact-core`.

#![deny(clippy::all)]

use napi_derive::napi;
use std::collections::HashMap;

/// Returns the library version string.
#[napi]
pub fn version() -> String {
    env!("CARGO_PKG_VERSION").to_owned()
}

/// The result of a `redact` call.
#[napi(object)]
pub struct RedactResult {
    /// Redacted text with numbered placeholder tokens, e.g. `"[EMAIL_1]"`.
    pub text: String,
    /// Maps each placeholder to the original value it replaced.
    pub tokens: HashMap<String, String>,
}

/// Redact PII in `text`.
///
/// Returns `{ text: string, tokens: Record<string, string> }` where `text` is
/// the redacted string and `tokens` maps placeholders to original values.
///
/// Output is byte-identical to the Python and Swift bindings for the same input.
#[napi]
pub fn redact(text: String) -> RedactResult {
    let result = ogentic_redact_core::redact_one_way(&text);
    RedactResult {
        text: result.text,
        tokens: result.tokens,
    }
}

/// Restore redacted placeholders in `text` using the `tokens` map from a prior
/// `redact` call.
#[napi]
pub fn unredact(text: String, tokens: HashMap<String, String>) -> String {
    ogentic_redact_core::unredact_one_way(&text, &tokens)
}
