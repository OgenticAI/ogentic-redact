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
    /// Redacted text with salted placeholder tokens, e.g. `"[Email_3f8a2c1b]"`.
    pub text: String,
    /// Maps each placeholder to the original value it replaced.
    pub tokens: HashMap<String, String>,
}

impl From<ogentic_redact_core::RedactOneWayResult> for RedactResult {
    fn from(r: ogentic_redact_core::RedactOneWayResult) -> Self {
        RedactResult {
            text: r.text,
            tokens: r.tokens,
        }
    }
}

/// Redact PII in `text` (ADR-0003 grammar `[Label_<salted-hex>]`).
///
/// Returns `{ text: string, tokens: Record<string, string> }`. Uses a fresh
/// per-call salt, so the same value redacts differently across calls; use
/// `redactWithSalt` for reproducible output.
#[napi]
pub fn redact(text: String) -> RedactResult {
    ogentic_redact_core::redact_one_way(&text).into()
}

/// Like `redact`, but with an explicit `salt` (bytes) so the salted-hex tokens
/// are reproducible. Surfaces sharing the same salt produce byte-identical
/// output — the basis of the cross-language conformance vectors.
#[napi]
pub fn redact_with_salt(text: String, salt: napi::bindgen_prelude::Buffer) -> RedactResult {
    ogentic_redact_core::redact_one_way_with_salt(&text, salt.as_ref()).into()
}

/// Restore redacted placeholders in `text` using the `tokens` map from a prior
/// `redact` call.
#[napi]
pub fn unredact(text: String, tokens: HashMap<String, String>) -> String {
    ogentic_redact_core::unredact_one_way(&text, &tokens)
}
