//! PyO3 binding for `ogentic-redact`.
//!
//! Exposes:
//! - `__version__` — library version string.
//! - `redact(text) -> dict` — one-way redaction; returns
//!   `{"text": str, "tokens": dict[str, str]}`.
//! - `unredact(text, tokens) -> str` — restore redacted text from the token map.

use pyo3::prelude::*;
use pyo3::types::PyDict;
use std::collections::HashMap;

/// `_native` Python extension module.
#[pymodule]
fn _native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    m.add_function(wrap_pyfunction!(redact, m)?)?;
    m.add_function(wrap_pyfunction!(redact_with_salt, m)?)?;
    m.add_function(wrap_pyfunction!(unredact, m)?)?;
    Ok(())
}

/// Build the `{"text", "tokens"}` dict from a core result.
fn result_to_dict<'py>(
    py: Python<'py>,
    result: &ogentic_redact_core::RedactOneWayResult,
) -> PyResult<Bound<'py, PyDict>> {
    let d = PyDict::new(py);
    d.set_item("text", &result.text)?;
    let tokens_dict = PyDict::new(py);
    for (k, v) in &result.tokens {
        tokens_dict.set_item(k, v)?;
    }
    d.set_item("tokens", tokens_dict)?;
    Ok(d)
}

/// Redact PII in `text` (ADR-0003 grammar `[Label_<salted-hex>]`).
///
/// Returns a dict ``{"text": str, "tokens": dict[str, str]}`` where ``text``
/// is the redacted string and ``tokens`` maps each placeholder (e.g.
/// ``"[Email_3f8a2c1b]"``) to the original value it replaced. Uses a fresh
/// per-call salt; use :func:`redact_with_salt` for reproducible output.
#[pyfunction]
fn redact<'py>(py: Python<'py>, text: &str) -> PyResult<Bound<'py, PyDict>> {
    result_to_dict(py, &ogentic_redact_core::redact_one_way(text))
}

/// Like :func:`redact`, but with an explicit ``salt`` (bytes) so the salted-hex
/// tokens are reproducible. Surfaces sharing the same salt produce byte-identical
/// output — the basis of the cross-language conformance vectors.
#[pyfunction]
fn redact_with_salt<'py>(py: Python<'py>, text: &str, salt: &[u8]) -> PyResult<Bound<'py, PyDict>> {
    result_to_dict(
        py,
        &ogentic_redact_core::redact_one_way_with_salt(text, salt),
    )
}

/// Restore redacted placeholders in `text` using `tokens`.
///
/// `tokens` must be the dict from the ``"tokens"`` field of a prior
/// :func:`redact` call.
#[pyfunction]
fn unredact(_py: Python<'_>, text: &str, tokens: HashMap<String, String>) -> PyResult<String> {
    Ok(ogentic_redact_core::unredact_one_way(text, &tokens))
}
