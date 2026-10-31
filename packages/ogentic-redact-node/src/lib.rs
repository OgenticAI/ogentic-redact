//! Safe one-way redaction and explicit, instance-scoped reversible redaction.
//! The built-in EMAIL/PHONE/US_SSN scanner is a development convenience.

#![deny(clippy::all)]

use napi_derive::napi;
use ogentic_redact_core::{MappingStore, RedactError, RedactMode, RestorationLimits};
use std::collections::HashMap;

#[napi]
pub fn version() -> String {
    env!("CARGO_PKG_VERSION").to_owned()
}

/// A one-way result. It never contains original values or a reversal map.
#[napi(object)]
pub struct RedactResult {
    pub text: String,
    pub redaction_count: u32,
}

impl From<ogentic_redact_core::RedactOneWayResult> for RedactResult {
    fn from(r: ogentic_redact_core::RedactOneWayResult) -> Self {
        Self {
            text: r.text,
            redaction_count: r.redaction_count as u32,
        }
    }
}

#[napi]
pub fn redact(text: String) -> RedactResult {
    ogentic_redact_core::redact_one_way(&text).into()
}

/// Deterministic one-way output for a caller-supplied salt; never returns PII.
#[napi]
pub fn redact_with_salt(text: String, salt: napi::bindgen_prelude::Buffer) -> RedactResult {
    ogentic_redact_core::redact_one_way_with_salt(&text, salt.as_ref()).into()
}

/// Legacy explicit-map restoration. New reversible callers should use ReversibleRedactor.
#[napi]
pub fn unredact(
    text: String,
    tokens: HashMap<String, String>,
    max_output_bytes: Option<f64>,
    max_replacements: Option<f64>,
) -> napi::Result<String> {
    ogentic_redact_core::unredact_one_way_with_limits(
        &text,
        &tokens,
        restoration_limits(max_output_bytes, max_replacements)?,
    )
    .map_err(restore_error)
}

fn restoration_limits(
    bytes: Option<f64>,
    replacements: Option<f64>,
) -> napi::Result<RestorationLimits> {
    fn budget(value: Option<f64>, default: usize) -> napi::Result<usize> {
        match value {
            None => Ok(default),
            Some(value)
                if value.is_finite()
                    && value >= 0.0
                    && value.fract() == 0.0
                    && value <= 9_007_199_254_740_991.0
                    && value <= usize::MAX as f64 =>
            {
                Ok(value as usize)
            },
            _ => Err(napi::Error::from_reason(
                "restoration limits must be nonnegative safe integers",
            )),
        }
    }
    let defaults = RestorationLimits::default();
    Ok(RestorationLimits {
        max_output_bytes: budget(bytes, defaults.max_output_bytes)?,
        max_replacements: budget(replacements, defaults.max_replacements)?,
    })
}

fn restore_error(error: RedactError) -> napi::Error {
    napi::Error::from_reason(match error {
        RedactError::UnknownMappingId { .. } => "mapping not found",
        RedactError::RestorationLimitExceeded => "restoration limit exceeded",
        RedactError::RestorationAllocationFailed => "unable to allocate restored output",
        _ => "restoration failed",
    })
}

#[napi(object)]
pub struct ReversibleResult {
    pub text: String,
    pub mapping_id: String,
}

/// Explicit opt-in to reversible redaction. Originals stay in this instance.
/// Call delete() or consume during unredact() when a mapping is no longer needed.
#[napi]
pub struct ReversibleRedactor {
    store: MappingStore,
    limits: RestorationLimits,
}

#[napi]
impl ReversibleRedactor {
    #[napi(constructor)]
    pub fn new(max_output_bytes: Option<f64>, max_replacements: Option<f64>) -> napi::Result<Self> {
        Ok(Self {
            store: MappingStore::new(),
            limits: restoration_limits(max_output_bytes, max_replacements)?,
        })
    }

    #[napi]
    pub fn redact(&self, text: String) -> napi::Result<ReversibleResult> {
        let (text, mapping_id) = ogentic_redact_core::redact(
            &text,
            "default",
            RedactMode::Reversible,
            Some(&self.store),
        )
        .map_err(|_| napi::Error::from_reason("redaction failed"))?;
        let mapping_id = mapping_id.ok_or_else(|| napi::Error::from_reason("redaction failed"))?;
        Ok(ReversibleResult { text, mapping_id })
    }

    #[napi]
    pub fn unredact(
        &self,
        text: String,
        mapping_id: String,
        consume: Option<bool>,
    ) -> napi::Result<String> {
        let result = if consume.unwrap_or(false) {
            ogentic_redact_core::unredact_and_delete_with_limits(
                &text,
                &mapping_id,
                &self.store,
                self.limits,
            )
        } else {
            ogentic_redact_core::unredact_with_limits(&text, &mapping_id, &self.store, self.limits)
        };
        result.map_err(restore_error)
    }

    #[napi]
    pub fn delete(&self, mapping_id: String) -> bool {
        self.store.delete(&mapping_id)
    }
}

impl Default for ReversibleRedactor {
    fn default() -> Self {
        Self {
            store: MappingStore::new(),
            limits: RestorationLimits::default(),
        }
    }
}
