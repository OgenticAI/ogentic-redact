//! `ogentic-redact-rules` — rule-pack loader for `ogentic-redact-core`.
//!
//! This crate provides the format specification and loader for entity-detection
//! rule packs (PHI / privilege / MNPI). Rule packs are JSON-based definitions of
//! entity patterns, recognizers, and precedence groups for the overlap resolver.
//!
//! # Quick start
//!
//! ```rust
//! use ogentic_redact_rules::{Loader, RulePackCategory};
//!
//! let loader = Loader::new();
//! let phi_pack = loader.load_pack(RulePackCategory::PHI)
//!     .expect("PHI pack must load");
//! assert_eq!(phi_pack.category, RulePackCategory::PHI);
//! ```

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

mod loader;
pub use loader::Loader;

/// Errors returned by rule-pack loading and validation.
#[derive(Debug, Clone, Error)]
pub enum RulePackError {
    /// Rule pack JSON is malformed or missing required fields.
    #[error("invalid rule pack: {reason}")]
    InvalidPack {
        /// Human-readable description of what made the pack invalid.
        reason: String,
    },

    /// Rule pack regex pattern does not compile.
    #[error("invalid regex pattern in {entity_type}: {pattern}")]
    InvalidPattern {
        /// The entity type whose pattern failed to compile.
        entity_type: String,
        /// The offending regex pattern.
        pattern: String,
    },

    /// Unknown category requested.
    #[error("unknown rule pack category: {category}")]
    UnknownCategory {
        /// The category string that was not recognised.
        category: String,
    },

    /// JSON deserialization error.
    #[error("failed to parse rule pack JSON: {0}")]
    SerdeError(String),

    /// Rule pack not found.
    #[error("rule pack not found: {category}")]
    PackNotFound {
        /// The category whose pack could not be located.
        category: String,
    },
}

/// Categories of rule packs in the system.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum RulePackCategory {
    /// Privilege-related entities (attorney-client, work product, etc).
    #[serde(rename = "PRIVILEGE")]
    Privilege,

    /// Protected health information (medical records, diagnoses, etc).
    #[serde(rename = "PHI")]
    PHI,

    /// Material non-public information (financial, earnings, etc).
    #[serde(rename = "MNPI")]
    MNPI,
}

impl RulePackCategory {
    /// Returns the string representation of the category.
    pub fn as_str(&self) -> &'static str {
        match self {
            RulePackCategory::Privilege => "privilege",
            RulePackCategory::PHI => "phi",
            RulePackCategory::MNPI => "mnpi",
        }
    }
}

impl std::fmt::Display for RulePackCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// A single entity pattern definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pattern {
    /// The regex pattern string (must compile).
    pub regex: String,
}

/// A recognizer definition (e.g., "email", "phone").
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Recognizer {
    /// Type of recognizer ("builtin" or "custom").
    pub recognizer_type: String,

    /// Name of the recognizer (e.g., "email", "phone").
    pub name: String,
}

/// An entity type definition with patterns and recognizers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntityType {
    /// The entity type label (e.g., "LEGAL_PRIVILEGE", "MEDICAL_DIAGNOSIS").
    pub entity_type: String,

    /// Regex patterns for this entity.
    pub patterns: Vec<Pattern>,

    /// Recognizers for this entity.
    #[serde(default)]
    pub recognizers: Vec<Recognizer>,
}

/// A complete rule pack definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RulePack {
    /// Category of this rule pack (privilege, PHI, MNPI).
    pub category: RulePackCategory,

    /// Precedence group identifier used by the R5 overlap resolver.
    pub precedence_group: String,

    /// Entity type definitions in this pack.
    pub entities: Vec<EntityType>,
}

impl RulePack {
    /// Validates the rule pack structure.
    /// Returns an error if any pattern fails to compile as a regex.
    pub fn validate(&self) -> Result<(), RulePackError> {
        for entity in &self.entities {
            for pattern in &entity.patterns {
                regex::Regex::new(&pattern.regex).map_err(|_| RulePackError::InvalidPattern {
                    entity_type: entity.entity_type.clone(),
                    pattern: pattern.regex.clone(),
                })?;
            }
        }
        Ok(())
    }
}
