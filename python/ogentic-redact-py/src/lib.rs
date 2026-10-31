//! Python one-way primitives. Raw mapping adapters are private to the package.
use ogentic_redact_core::{RestorationLimits, DEFAULT_MAX_OUTPUT_BYTES, DEFAULT_MAX_REPLACEMENTS};
use pyo3::exceptions::{PyTypeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyBool, PyDict, PyInt};
use std::collections::HashMap;

#[pymodule]
fn _native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    m.add_function(wrap_pyfunction!(redact, m)?)?;
    m.add_function(wrap_pyfunction!(redact_with_salt, m)?)?;
    m.add_function(wrap_pyfunction!(unredact, m)?)?;
    m.add_function(wrap_pyfunction!(_redact_to_mapping, m)?)?;
    m.add_function(wrap_pyfunction!(_redact_to_mapping_with_salt, m)?)?;
    Ok(())
}

fn result_to_dict(
    py: Python<'_>,
    result: ogentic_redact_core::RedactOneWayResult,
) -> PyResult<Bound<'_, PyDict>> {
    let d = PyDict::new(py);
    d.set_item("text", result.text)?;
    d.set_item("redaction_count", result.redaction_count)?;
    Ok(d)
}

fn mapping_to_dict(
    py: Python<'_>,
    result: ogentic_redact_core::RedactMappingResult,
) -> PyResult<Bound<'_, PyDict>> {
    let d = PyDict::new(py);
    d.set_item("text", result.text)?;
    d.set_item("tokens", result.tokens)?;
    Ok(d)
}

/// One-way result containing text and a count, never original values.
#[pyfunction]
fn redact<'py>(py: Python<'py>, text: &str) -> PyResult<Bound<'py, PyDict>> {
    result_to_dict(py, ogentic_redact_core::redact_one_way(text))
}

#[pyfunction]
fn redact_with_salt<'py>(py: Python<'py>, text: &str, salt: &[u8]) -> PyResult<Bound<'py, PyDict>> {
    result_to_dict(
        py,
        ogentic_redact_core::redact_one_way_with_salt(text, salt),
    )
}

/// INTERNAL: sensitive result for trusted mapping-store adapters; never forward inline.
#[pyfunction]
fn _redact_to_mapping<'py>(py: Python<'py>, text: &str) -> PyResult<Bound<'py, PyDict>> {
    mapping_to_dict(py, ogentic_redact_core::redact_to_mapping(text))
}

/// INTERNAL: deterministic sensitive result for mapping-store conformance.
#[pyfunction]
fn _redact_to_mapping_with_salt<'py>(
    py: Python<'py>,
    text: &str,
    salt: &[u8],
) -> PyResult<Bound<'py, PyDict>> {
    mapping_to_dict(
        py,
        ogentic_redact_core::redact_to_mapping_with_salt(text, salt),
    )
}

/// Strict Python integer budget (bool and float are not accepted).
struct NonNegativeLimit(usize);
impl FromPyObject<'_, '_> for NonNegativeLimit {
    type Error = PyErr;
    fn extract(obj: Borrowed<'_, '_, PyAny>) -> PyResult<Self> {
        if obj.is_instance_of::<PyBool>() || !obj.is_instance_of::<PyInt>() {
            return Err(PyTypeError::new_err(
                "restoration limits must be nonnegative integers",
            ));
        }
        obj.extract::<usize>().map(Self).map_err(|_| {
            PyValueError::new_err("restoration limits must be nonnegative platform-sized integers")
        })
    }
}

#[pyfunction(signature = (text, tokens, *, max_output_bytes=NonNegativeLimit(DEFAULT_MAX_OUTPUT_BYTES), max_replacements=NonNegativeLimit(DEFAULT_MAX_REPLACEMENTS)))]
fn unredact(
    text: &str,
    tokens: HashMap<String, String>,
    max_output_bytes: NonNegativeLimit,
    max_replacements: NonNegativeLimit,
) -> PyResult<String> {
    ogentic_redact_core::unredact_one_way_with_limits(
        text,
        &tokens,
        RestorationLimits {
            max_output_bytes: max_output_bytes.0,
            max_replacements: max_replacements.0,
        },
    )
    .map_err(|error| PyValueError::new_err(error.to_string()))
}
