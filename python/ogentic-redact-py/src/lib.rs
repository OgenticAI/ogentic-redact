//! PyO3 binding for `ogentic-redact`.
//!
//! Exposes:
//! - `__version__` — library version string.
//! - `redact(text) -> dict` — one-way redaction; returns
//!   `{"text": str, "tokens": dict[str, str]}`.
//! - `unredact(text, tokens) -> str` — restore redacted text from the token map.

// PyO3 0.22 macro expansion produces useless Into<PyErr> conversions that
// clippy flags as `useless_conversion`.  Suppress at the crate level.
#![allow(clippy::useless_conversion)]

use pyo3::prelude::*;
use pyo3::types::PyDict;
use std::collections::HashMap;

/// `_native` Python extension module.
#[pymodule]
fn _native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    m.add_function(wrap_pyfunction!(redact, m)?)?;
    m.add_function(wrap_pyfunction!(unredact, m)?)?;
    Ok(())
}

/// Redact PII in `text`.
///
/// Returns a dict ``{"text": str, "tokens": dict[str, str]}`` where ``text``
/// is the redacted string and ``tokens`` maps each placeholder (e.g.
/// ``"[EMAIL_1]"``) to the original value it replaced.
///
/// Output is byte-identical to the Node.js and Swift bindings for the same input.
#[pyfunction]
fn redact(py: Python<'_>, text: &str) -> PyResult<PyObject> {
    let result = ogentic_redact_core::redact_one_way(text);
    let d = PyDict::new_bound(py);
    d.set_item("text", &result.text)?;
    let tokens_dict = PyDict::new_bound(py);
    for (k, v) in &result.tokens {
        tokens_dict.set_item(k, v)?;
    }
    d.set_item("tokens", tokens_dict)?;
    Ok(d.into())
}

/// Restore redacted placeholders in `text` using `tokens`.
///
/// `tokens` must be the dict from the ``"tokens"`` field of a prior
/// :func:`redact` call.
#[pyfunction]
fn unredact(_py: Python<'_>, text: &str, tokens: HashMap<String, String>) -> PyResult<String> {
    Ok(ogentic_redact_core::unredact_one_way(text, &tokens))
}
