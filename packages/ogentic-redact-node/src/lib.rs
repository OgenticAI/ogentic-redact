//! napi-rs binding stub for `ogentic-redact`.
//!
//! This module will expose the Redactor API to Node.js once the core detection
//! logic lands. For F1 it establishes the crate and module boundary only.

#![deny(clippy::all)]

use napi_derive::napi;

/// Returns the library version string.
#[napi]
pub fn version() -> String {
    env!("CARGO_PKG_VERSION").to_owned()
}
