//! PyO3 binding stub for `ogentic-redact`.
//!
//! This module will expose the Redactor API to Python once the core detection
//! logic lands. For F1 it establishes the crate and module boundary only.

use pyo3::prelude::*;

/// `ogentic_redact` Python module.
#[pymodule]
fn ogentic_redact(_py: Python<'_>, m: &PyModule) -> PyResult<()> {
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    Ok(())
}
