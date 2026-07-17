//! PyO3 binding stub for `ogentic-redact`.
//!
//! This module will expose the Redactor API to Python once the core detection
//! logic lands. For F1 it establishes the crate and module boundary only.

use pyo3::prelude::*;

/// `ogentic_redact` Python module.
#[pymodule]
fn _native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    Ok(())
}
