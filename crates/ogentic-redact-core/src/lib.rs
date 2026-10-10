//! On-device sensitive-content substitution and reversible mapping storage.
//!
//! Production callers supply validated UTF-8 byte spans to [`redact_spans`].
//! Scanner helpers detect EMAIL/PHONE/SSN as a development convenience only.
//! One-way APIs return no reversal mapping; explicit reversible APIs keep the
//! mapping in a separate [`MappingStore`].
//!
//! ```rust
//! use ogentic_redact_core::{MappingStore, RedactMode, redact, unredact_and_delete};
//! let store = MappingStore::new();
//! let original = "Contact alice@example.com.";
//! let (text, id) = redact(original, "default", RedactMode::Reversible, Some(&store))?;
//! assert_eq!(unredact_and_delete(&text, &id.unwrap(), &store)?, original);
//! # Ok::<(), ogentic_redact_core::RedactError>(())
//! ```

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use std::{
    collections::{HashMap, HashSet},
    fmt,
    sync::{Arc, Mutex},
};

use thiserror::Error;

pub mod token;

/// Errors from redaction, span validation, or mapping lookup.
#[derive(Debug, Clone, Error)]
pub enum RedactError {
    /// The requested development-scanner profile is unknown.
    #[error("unknown redaction profile: {profile:?}")]
    UnknownProfile {
        /// Unrecognised profile name.
        profile: String,
    },
    /// Reversible operation requires a separate store.
    #[error("reversible mode requires a mapping_store reference")]
    MappingStoreRequired,
    /// No mapping exists for the supplied identifier.
    #[error("unknown mapping id: {mapping_id:?}")]
    UnknownMappingId {
        /// Identifier that could not be resolved.
        mapping_id: String,
    },
    /// A span is empty, reversed, out of bounds, or splits a UTF-8 character.
    #[error("invalid UTF-8 byte span at index {index}")]
    InvalidSpan {
        /// Index in the caller-supplied span list.
        index: usize,
    },
    /// A span has an empty entity type.
    #[error("empty entity type at span index {index}")]
    InvalidEntityType {
        /// Index in the caller-supplied span list.
        index: usize,
    },
    /// Caller spans overlap; resolve policy before invoking substitution.
    #[error("overlapping spans must be resolved before redaction")]
    OverlappingSpans,
    /// Restoration would exceed the configured UTF-8 byte or replacement budget.
    #[error("restoration limit exceeded")]
    RestorationLimitExceeded,
    /// Memory for the bounded restored result could not be reserved.
    #[error("unable to allocate restored output")]
    RestorationAllocationFailed,
}

/// Default maximum restored UTF-8 output size (16 MiB).
pub const DEFAULT_MAX_OUTPUT_BYTES: usize = 16 * 1024 * 1024;
/// Default maximum number of mapped token replacements in one restoration.
pub const DEFAULT_MAX_REPLACEMENTS: usize = 100_000;

/// Resource budgets for restoration of potentially untrusted model output.
/// Zero is permitted: a zero byte budget accepts only empty output, and a zero
/// replacement budget permits only text with no mapped tokens.
#[derive(Debug, Clone, Copy)]
pub struct RestorationLimits {
    /// Maximum complete restored output size in UTF-8 bytes.
    pub max_output_bytes: usize,
    /// Maximum count of mapped token occurrences, including repetitions.
    pub max_replacements: usize,
}

impl Default for RestorationLimits {
    fn default() -> Self {
        Self {
            max_output_bytes: DEFAULT_MAX_OUTPUT_BYTES,
            max_replacements: DEFAULT_MAX_REPLACEMENTS,
        }
    }
}

/// Whether originals are discarded or kept in a separate store.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedactMode {
    /// Retain originals in the explicitly supplied store.
    Reversible,
    /// Return redacted text without retaining a reversal mapping.
    OneWay,
}

/// A sensitive span in the original text, using UTF-8 **byte** offsets.
///
/// Both offsets must be character boundaries. Bindings whose callers use
/// character or UTF-16 offsets must convert before calling the Rust API.
#[derive(Debug, Clone)]
pub struct Span {
    /// First byte, inclusive.
    pub start: usize,
    /// Final byte, exclusive.
    pub end: usize,
    /// Entity category, mapped to a grammar-safe token label.
    pub entity_type: String,
}

/// In-process reversible mappings with explicit deletion and safe diagnostics.
///
/// Identifiers contain 128 random bits. The store does not provide tenant
/// authorization or automatic expiry; callers must scope stores and invoke
/// [`MappingStore::delete`] or [`unredact_and_delete`] when records are no longer
/// needed. Dropping a store releases every remaining record.
#[derive(Default)]
pub struct MappingStore {
    mappings: Mutex<HashMap<String, Arc<MappingRecord>>>,
}

struct MappingRecord {
    // Retained for future store persistence; never exposed by Debug.
    _call_salt: Vec<u8>,
    entries: HashMap<String, String>,
}

impl fmt::Debug for MappingStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MappingStore")
            .field("records", &self.len())
            .finish()
    }
}

impl MappingStore {
    /// Create an empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Delete one record, returning whether it existed.
    ///
    /// Concurrent restorations that already obtained the record may complete.
    pub fn delete(&self, mapping_id: &str) -> bool {
        self.take(mapping_id).is_some()
    }

    /// Number of retained records; contains no sensitive information.
    pub fn len(&self) -> usize {
        self.mappings
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .len()
    }

    /// Whether the store contains no records.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn put(&self, record: MappingRecord) -> String {
        let mut mappings = self.mappings.lock().unwrap_or_else(|e| e.into_inner());
        loop {
            let random: [u8; 16] = rand::random();
            let id = format!("map_{:032x}", u128::from_be_bytes(random));
            if let std::collections::hash_map::Entry::Vacant(entry) = mappings.entry(id.clone()) {
                entry.insert(Arc::new(record));
                return id;
            }
        }
    }

    fn get(&self, mapping_id: &str) -> Option<Arc<MappingRecord>> {
        self.mappings
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(mapping_id)
            .cloned()
    }

    fn take(&self, mapping_id: &str) -> Option<Arc<MappingRecord>> {
        self.mappings
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(mapping_id)
    }
}

const KNOWN_PROFILES: &[&str] = &["default", "pii", "phi"];

/// Assign distinct tokens to distinct exact originals, including case/spacing.
/// Source token literals are reserved so restoration cannot reinterpret them.
#[derive(Default)]
struct TokenAssigner {
    seen: HashMap<(String, String), String>,
    occupied: HashSet<String>,
}

impl TokenAssigner {
    fn for_text(text: &str) -> Self {
        Self {
            seen: HashMap::new(),
            occupied: token::parse_tokens(text)
                .iter()
                .map(token::ParsedToken::as_token)
                .collect(),
        }
    }

    fn assign(&mut self, label: &str, original: &str, call_salt: &[u8]) -> String {
        let full = token::full_discriminator(call_salt, label, original);
        self.assign_digest(label, original, &full)
    }

    fn assign_digest(&mut self, label: &str, original: &str, full: &str) -> String {
        let key = (label.to_owned(), original.to_owned());
        if let Some(existing) = self.seen.get(&key) {
            return existing.clone();
        }
        let mut length = token::DISCRIMINATOR_LEN;
        let mut suffix = 0usize;
        loop {
            let discriminator = if length <= full.len() {
                full[..length].to_owned()
            } else {
                // Even a full-digest collision or reserved full-digest literal
                // is resolved deterministically; the grammar permits extension.
                format!("{full}{suffix:x}")
            };
            let candidate = token::emit(label, &discriminator);
            if self.occupied.insert(candidate.clone()) {
                self.seen.insert(key, candidate.clone());
                return candidate;
            }
            if length < full.len() {
                length = (length + 4).min(full.len());
            } else {
                length = full.len() + 1;
                suffix += 1;
            }
        }
    }
}

/// Redact with the built-in EMAIL/PHONE/SSN development scanner.
///
/// `profile` accepts `default`, `pii`, or `phi` as compatibility names; each
/// uses the same limited scanner. Production callers should use [`redact_spans`].
/// Reversible mode requires a store and returns its opaque mapping identifier.
///
/// # Errors
/// Returns [`RedactError::UnknownProfile`] for an unknown profile or
/// [`RedactError::MappingStoreRequired`] when reversible mode lacks a store.
pub fn redact(
    text: &str,
    profile: &str,
    mode: RedactMode,
    mapping_store: Option<&MappingStore>,
) -> Result<(String, Option<String>), RedactError> {
    let salt: [u8; token::SALT_LEN] = rand::random();
    redact_with_salt(text, profile, mode, mapping_store, &salt)
}

/// [`redact`] with an explicit salt, for deterministic conformance tests.
///
/// Production callers should use [`redact`] so independent calls are unlinkable.
///
/// # Errors
/// Has the same profile and store requirements as [`redact`].
pub fn redact_with_salt(
    text: &str,
    profile: &str,
    mode: RedactMode,
    mapping_store: Option<&MappingStore>,
    call_salt: &[u8],
) -> Result<(String, Option<String>), RedactError> {
    if !KNOWN_PROFILES.contains(&profile) {
        return Err(RedactError::UnknownProfile {
            profile: profile.to_owned(),
        });
    }
    redact_spans_with_salt(text, &detect_entities(text), mode, mapping_store, call_salt)
}

/// Substitute caller-provided sensitive spans after validating every offset.
///
/// Spans may be unsorted; they must be nonempty, disjoint UTF-8 byte ranges with
/// nonempty entity types. Overlap is rejected instead of silently dropping
/// sensitive coverage. Callers must apply their category/group policy first;
/// this entry point does not yet implement category precedence.
///
/// # Errors
/// Returns [`RedactError::InvalidSpan`], [`RedactError::InvalidEntityType`], or
/// [`RedactError::OverlappingSpans`] before creating any mapping. Reversible
/// operation without a store returns [`RedactError::MappingStoreRequired`].
pub fn redact_spans(
    text: &str,
    spans: &[Span],
    mode: RedactMode,
    mapping_store: Option<&MappingStore>,
) -> Result<(String, Option<String>), RedactError> {
    let salt: [u8; token::SALT_LEN] = rand::random();
    redact_spans_with_salt(text, spans, mode, mapping_store, &salt)
}

/// Deterministic-salt variant of [`redact_spans`] for conformance testing.
///
/// # Errors
/// Has the same validation and store requirements as [`redact_spans`].
pub fn redact_spans_with_salt(
    text: &str,
    spans: &[Span],
    mode: RedactMode,
    mapping_store: Option<&MappingStore>,
    call_salt: &[u8],
) -> Result<(String, Option<String>), RedactError> {
    if mode == RedactMode::Reversible && mapping_store.is_none() {
        return Err(RedactError::MappingStoreRequired);
    }
    let mut sorted: Vec<&Span> = Vec::with_capacity(spans.len());
    for (index, span) in spans.iter().enumerate() {
        if span.start >= span.end
            || span.end > text.len()
            || !text.is_char_boundary(span.start)
            || !text.is_char_boundary(span.end)
        {
            return Err(RedactError::InvalidSpan { index });
        }
        if span.entity_type.trim().is_empty() {
            return Err(RedactError::InvalidEntityType { index });
        }
        sorted.push(span);
    }
    sorted.sort_by_key(|span| span.start);
    if sorted.windows(2).any(|pair| pair[0].end > pair[1].start) {
        return Err(RedactError::OverlappingSpans);
    }
    let result = substitute_spans(text, &sorted, call_salt, mode == RedactMode::Reversible);
    let id = if let Some(store) = mapping_store.filter(|_| mode == RedactMode::Reversible) {
        Some(store.put(MappingRecord {
            _call_salt: call_salt.to_vec(),
            entries: result.tokens,
        }))
    } else {
        None
    };
    Ok((result.text, id))
}

/// Restore present tokens using the selected mapping and default resource limits.
/// Unknown tokens are preserved and originals are never rescanned.
///
/// # Errors
/// Returns a missing-mapping, resource-limit, or allocation error. The mapping
/// remains available after success or failure.
pub fn unredact(
    text: &str,
    mapping_id: &str,
    mapping_store: &MappingStore,
) -> Result<String, RedactError> {
    unredact_with_limits(
        text,
        mapping_id,
        mapping_store,
        RestorationLimits::default(),
    )
}

/// [`unredact`] with explicit UTF-8 output and replacement budgets.
///
/// # Errors
/// Returns a missing-mapping, resource-limit, or allocation error.
pub fn unredact_with_limits(
    text: &str,
    mapping_id: &str,
    mapping_store: &MappingStore,
    limits: RestorationLimits,
) -> Result<String, RedactError> {
    let record = mapping_store
        .get(mapping_id)
        .ok_or_else(|| RedactError::UnknownMappingId {
            mapping_id: mapping_id.to_owned(),
        })?;
    unredact_one_way_with_limits(text, &record.entries, limits)
}

/// Restore within default limits and atomically consume the mapping on success.
/// Failed validation/allocation leaves it available. Concurrent consuming calls
/// have one winner; already-started non-consuming lookups may still finish.
///
/// # Errors
/// Returns a missing-mapping, resource-limit, or allocation error.
pub fn unredact_and_delete(
    text: &str,
    mapping_id: &str,
    mapping_store: &MappingStore,
) -> Result<String, RedactError> {
    unredact_and_delete_with_limits(
        text,
        mapping_id,
        mapping_store,
        RestorationLimits::default(),
    )
}

/// [`unredact_and_delete`] with explicit resource budgets.
/// Output is fully validated and constructed before removing the immutable
/// record. A rejected restoration never consumes its mapping.
///
/// # Errors
/// Returns a missing-mapping error if another consumer wins, or a limit or
/// allocation error without removing the record.
pub fn unredact_and_delete_with_limits(
    text: &str,
    mapping_id: &str,
    mapping_store: &MappingStore,
    limits: RestorationLimits,
) -> Result<String, RedactError> {
    let record = mapping_store
        .get(mapping_id)
        .ok_or_else(|| RedactError::UnknownMappingId {
            mapping_id: mapping_id.to_owned(),
        })?;
    let restored = unredact_one_way_with_limits(text, &record.entries, limits)?;
    let mut mappings = mapping_store
        .mappings
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    if mappings
        .get(mapping_id)
        .is_some_and(|current| Arc::ptr_eq(current, &record))
    {
        mappings.remove(mapping_id);
        Ok(restored)
    } else {
        Err(RedactError::UnknownMappingId {
            mapping_id: mapping_id.to_owned(),
        })
    }
}

/// Safe one-way result: contains redacted text and nonsensitive counts only.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RedactOneWayResult {
    /// Redacted text; no token-to-original mapping accompanies it.
    pub text: String,
    /// Number of sensitive spans replaced, including repeated values.
    pub redaction_count: usize,
}

impl RedactOneWayResult {
    /// Whether the development scanner found no sensitive spans.
    pub fn is_clean(&self) -> bool {
        self.redaction_count == 0
    }
}

/// Explicitly sensitive low-level result for mapping-store adapters.
///
/// **This value contains plaintext originals. Never forward or log it as a
/// redacted response.** Ordinary callers should use [`redact_one_way`] or a
/// separate [`MappingStore`]. It deliberately does not implement `Serialize`
/// or reveal originals through `Debug`.
#[derive(Clone)]
pub struct RedactMappingResult {
    /// Redacted text.
    pub text: String,
    /// Sensitive token-to-original table, for separate protected storage only.
    pub tokens: HashMap<String, String>,
}

impl fmt::Debug for RedactMappingResult {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RedactMappingResult")
            .field("entries", &self.tokens.len())
            .finish_non_exhaustive()
    }
}

/// Redact EMAIL/PHONE/SSN using the local development scanner, without retaining
/// or returning any reversal mapping. Production callers supply spans instead.
pub fn redact_one_way(text: &str) -> RedactOneWayResult {
    let salt: [u8; token::SALT_LEN] = rand::random();
    redact_one_way_with_salt(text, &salt)
}

/// Deterministic-salt [`redact_one_way`] for tests; returns no originals.
pub fn redact_one_way_with_salt(text: &str, call_salt: &[u8]) -> RedactOneWayResult {
    let spans = detect_entities(text);
    let sorted: Vec<_> = spans.iter().collect();
    let result = substitute_spans(text, &sorted, call_salt, false);
    RedactOneWayResult {
        text: result.text,
        redaction_count: spans.len(),
    }
}

/// Explicit low-level scanner operation returning plaintext originals.
///
/// **Sensitive:** keep the returned mapping separate from downstream text.
/// This is intended for CLI/private store adapters, not one-way responses.
pub fn redact_to_mapping(text: &str) -> RedactMappingResult {
    let salt: [u8; token::SALT_LEN] = rand::random();
    redact_to_mapping_with_salt(text, &salt)
}

/// Deterministic-salt [`redact_to_mapping`]; the returned mapping is sensitive.
pub fn redact_to_mapping_with_salt(text: &str, call_salt: &[u8]) -> RedactMappingResult {
    let spans = detect_entities(text);
    let sorted: Vec<_> = spans.iter().collect();
    substitute_spans(text, &sorted, call_salt, true)
}

fn substitute_spans(
    text: &str,
    spans: &[&Span],
    call_salt: &[u8],
    retain_mapping: bool,
) -> RedactMappingResult {
    let mut assigner = TokenAssigner::for_text(text);
    let mut out = String::with_capacity(text.len());
    let mut tokens = HashMap::new();
    let mut cursor = 0;
    for span in spans {
        let original = &text[span.start..span.end];
        let token = assigner.assign(&token::label_for(&span.entity_type), original, call_salt);
        out.push_str(&text[cursor..span.start]);
        out.push_str(&token);
        if retain_mapping {
            tokens.entry(token).or_insert_with(|| original.to_owned());
        }
        cursor = span.end;
    }
    out.push_str(&text[cursor..]);
    RedactMappingResult { text: out, tokens }
}

/// Restore an explicitly supplied sensitive mapping within default limits.
/// A true [`redact_one_way`] result has no map and cannot be reversed.
///
/// # Errors
/// Returns a resource-limit or allocation error without partially returning text.
pub fn unredact_one_way(
    redacted: &str,
    tokens: &HashMap<String, String>,
) -> Result<String, RedactError> {
    unredact_one_way_with_limits(redacted, tokens, RestorationLimits::default())
}

/// Non-cascading restoration with allocation-free preflight and explicit limits.
/// Unknown tokens remain literal and restored originals are never rescanned.
///
/// # Errors
/// Returns [`RedactError::RestorationLimitExceeded`] before output allocation if
/// UTF-8 bytes or mapped occurrences exceed the budget, or
/// [`RedactError::RestorationAllocationFailed`] if reservation fails.
pub fn unredact_one_way_with_limits(
    redacted: &str,
    tokens: &HashMap<String, String>,
    limits: RestorationLimits,
) -> Result<String, RedactError> {
    let mut size = 0usize;
    let mut count = 0usize;
    let mut cursor = 0usize;
    for token in token::token_ranges(redacted) {
        size = size
            .checked_add(token.start - cursor)
            .ok_or(RedactError::RestorationLimitExceeded)?;
        let key = &redacted[token.start..token.end];
        let replacement_len = if let Some(original) = tokens.get(key) {
            count = count
                .checked_add(1)
                .ok_or(RedactError::RestorationLimitExceeded)?;
            original.len()
        } else {
            key.len()
        };
        size = size
            .checked_add(replacement_len)
            .ok_or(RedactError::RestorationLimitExceeded)?;
        if size > limits.max_output_bytes || count > limits.max_replacements {
            return Err(RedactError::RestorationLimitExceeded);
        }
        cursor = token.end;
    }
    size = size
        .checked_add(redacted.len() - cursor)
        .ok_or(RedactError::RestorationLimitExceeded)?;
    if size > limits.max_output_bytes {
        return Err(RedactError::RestorationLimitExceeded);
    }
    let mut out = String::new();
    out.try_reserve_exact(size)
        .map_err(|_| RedactError::RestorationAllocationFailed)?;
    cursor = 0;
    for token in token::token_ranges(redacted) {
        out.push_str(&redacted[cursor..token.start]);
        let key = &redacted[token.start..token.end];
        out.push_str(tokens.get(key).map_or(key, String::as_str));
        cursor = token.end;
    }
    out.push_str(&redacted[cursor..]);
    Ok(out)
}

// Shared development scanner. It is deliberately not a production detector.
fn detect_entities(text: &str) -> Vec<Span> {
    let bytes = text.as_bytes();
    let mut spans = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        let hit = match_email(bytes, i)
            .map(|(_, end)| ("EMAIL_ADDRESS", end))
            .or_else(|| match_ssn(bytes, i).map(|(_, end)| ("US_SSN", end)))
            .or_else(|| match_phone(bytes, i).map(|(_, end)| ("PHONE_NUMBER", end)));
        if let Some((entity_type, end)) = hit {
            spans.push(Span {
                start: i,
                end,
                entity_type: entity_type.to_owned(),
            });
            i = end;
        } else {
            i += text[i..]
                .chars()
                .next()
                .expect("nonempty remaining text")
                .len_utf8();
        }
    }
    spans
}

fn is_email_local_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'.' | b'+' | b'-' | b'_')
}

fn match_email(b: &[u8], pos: usize) -> Option<(String, usize)> {
    if pos > 0 && is_email_local_char(b[pos - 1]) {
        return None;
    }
    let mut i = pos;
    if i >= b.len() || !is_email_local_char(b[i]) {
        return None;
    }
    while i < b.len() && is_email_local_char(b[i]) {
        i += 1;
    }
    if i >= b.len() || b[i] != b'@' {
        return None;
    }
    let at = i;
    i += 1;
    if i >= b.len() || !b[i].is_ascii_alphanumeric() {
        return None;
    }
    while i < b.len() && (b[i].is_ascii_alphanumeric() || b[i] == b'.' || b[i] == b'-') {
        i += 1;
    }
    while i > at + 1 && b[i - 1] == b'.' {
        i -= 1;
    }
    if !b[at + 1..i].contains(&b'.') {
        return None;
    }
    Some((std::str::from_utf8(&b[pos..i]).ok()?.to_owned(), i))
}

fn match_ssn(b: &[u8], pos: usize) -> Option<(String, usize)> {
    if pos + 11 > b.len() {
        return None;
    }
    if pos > 0 && b[pos - 1].is_ascii_digit() {
        return None;
    }
    let s = &b[pos..pos + 11];
    if !(s[0].is_ascii_digit()
        && s[1].is_ascii_digit()
        && s[2].is_ascii_digit()
        && s[3] == b'-'
        && s[4].is_ascii_digit()
        && s[5].is_ascii_digit()
        && s[6] == b'-'
        && s[7].is_ascii_digit()
        && s[8].is_ascii_digit()
        && s[9].is_ascii_digit()
        && s[10].is_ascii_digit())
    {
        return None;
    }
    if pos + 11 < b.len() && b[pos + 11].is_ascii_digit() {
        return None;
    }
    Some((std::str::from_utf8(s).ok()?.to_owned(), pos + 11))
}

fn match_phone(b: &[u8], pos: usize) -> Option<(String, usize)> {
    if pos > 0 && (b[pos - 1].is_ascii_alphanumeric() || b[pos - 1] == b'.') {
        return None;
    }
    let rest = &b[pos..];

    // +1-NXX-NXX-XXXX
    if rest.starts_with(b"+1") && rest.len() >= 15 {
        let c = &rest[..15];
        if c[2] == b'-'
            && c[3..6].iter().all(|b| b.is_ascii_digit())
            && c[6] == b'-'
            && c[7..10].iter().all(|b| b.is_ascii_digit())
            && c[10] == b'-'
            && c[11..15].iter().all(|b| b.is_ascii_digit())
        {
            return Some((std::str::from_utf8(c).ok()?.to_owned(), pos + 15));
        }
    }

    // (NXX) NXX-XXXX
    if rest.len() >= 14 && rest[0] == b'(' {
        let c = &rest[..14];
        if c[1..4].iter().all(|b| b.is_ascii_digit())
            && c[4] == b')'
            && c[5] == b' '
            && c[6..9].iter().all(|b| b.is_ascii_digit())
            && c[9] == b'-'
            && c[10..14].iter().all(|b| b.is_ascii_digit())
        {
            return Some((std::str::from_utf8(c).ok()?.to_owned(), pos + 14));
        }
    }

    // NXX-NXX-XXXX
    if rest.len() >= 12
        && rest[0..3].iter().all(|b| b.is_ascii_digit())
        && rest[3] == b'-'
        && rest[4..7].iter().all(|b| b.is_ascii_digit())
        && rest[7] == b'-'
        && rest[8..12].iter().all(|b| b.is_ascii_digit())
    {
        let c = &rest[..12];
        return Some((std::str::from_utf8(c).ok()?.to_owned(), pos + 12));
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    // AC1: round-trip — redact → unredact → original text restored exactly.
    #[test]
    fn round_trip_restores_original() {
        let mapping_store = MappingStore::new();
        let text = "Contact alice@example.com for support.";
        let (redacted, mid_opt) = redact(
            text,
            "default",
            RedactMode::Reversible,
            Some(&mapping_store),
        )
        .unwrap();
        let mid = mid_opt.expect("reversible mode must produce a mapping_id");

        let toks = token::parse_tokens(&redacted);
        assert_eq!(toks.len(), 1, "one email → one token");
        assert_eq!(toks[0].label, "Email", "token must carry the Email label");
        assert!(
            !redacted.contains("alice@example.com"),
            "PII must not appear in redacted output"
        );

        let restored = unredact(&redacted, &mid, &mapping_store).unwrap();
        assert_eq!(
            restored, text,
            "round-trip must restore original text exactly"
        );
    }

    // AC2: unknown mapping_id → RedactError::UnknownMappingId (sanitised error).
    #[test]
    fn unknown_mapping_id_returns_domain_error() {
        let mapping_store = MappingStore::new();
        let err = unredact("[Email_deadbeef]", "map_0000000000000000", &mapping_store)
            .expect_err("unknown mapping_id must produce an error");
        assert!(
            matches!(err, RedactError::UnknownMappingId { .. }),
            "error must be UnknownMappingId, got: {err:?}"
        );
    }

    // AC3: tokens absent from the mapping_store mapping are left untouched.
    #[test]
    fn unknown_token_left_untouched() {
        let mapping_store = MappingStore::new();
        let text = "Hello alice@example.com!";
        let (redacted, mid_opt) = redact(
            text,
            "default",
            RedactMode::Reversible,
            Some(&mapping_store),
        )
        .unwrap();
        let mid = mid_opt.unwrap();

        // Inject a valid-grammar token that was NOT in this mapping.
        let with_foreign = format!("{redacted} and [Person_deadbeef]");
        let restored = unredact(&with_foreign, &mid, &mapping_store).unwrap();

        assert!(
            restored.contains("[Person_deadbeef]"),
            "foreign token must remain verbatim"
        );
        assert!(
            restored.contains("alice@example.com"),
            "known token must be restored"
        );
    }

    // AC4: no cross-mapping bleed — mapping scope is strictly isolated per mapping_id.
    //
    // Independently salted mappings must never resolve each other's tokens.
    #[test]
    fn no_cross_mapping_bleed() {
        let mapping_store = MappingStore::new();
        let text_a = "Contact alice@example.com.";
        let text_b = "Reach out to bob@example.org.";

        let (redacted_a, mid_a_opt) = redact(
            text_a,
            "default",
            RedactMode::Reversible,
            Some(&mapping_store),
        )
        .unwrap();
        let (_redacted_b, mid_b_opt) = redact(
            text_b,
            "default",
            RedactMode::Reversible,
            Some(&mapping_store),
        )
        .unwrap();
        let mid_a = mid_a_opt.unwrap();
        let mid_b = mid_b_opt.unwrap();

        // Mapping ids must be distinct.
        assert_ne!(mid_a, mid_b);

        // Correct mapping restores correctly.
        let restored_a = unredact(&redacted_a, &mid_a, &mapping_store).unwrap();
        assert_eq!(restored_a, text_a, "correct mapping must restore original");

        // Using mapping B's id to unredact mapping A's text must NOT restore text_a's
        // original — it resolves the token via mapping B's sub-map only.
        let cross = unredact(&redacted_a, &mid_b, &mapping_store).unwrap();
        assert_ne!(
            cross, text_a,
            "wrong mapping_id must not restore correct original — proves isolation"
        );
        // A foreign mapping must not introduce Alice's original.
        assert!(
            !cross.contains("alice@example.com"),
            "alice's PII must not appear when using mapping B"
        );
    }

    // AC5: failure-path for missing/expired mapping_id.
    #[test]
    fn missing_mapping_id_returns_error() {
        let mapping_store = MappingStore::new();
        let result = unredact(
            "text with [Email_deadbeef]",
            "map_does_not_exist",
            &mapping_store,
        );
        match result.expect_err("missing mapping must return an error") {
            RedactError::UnknownMappingId { mapping_id } => {
                assert_eq!(mapping_id, "map_does_not_exist");
            },
            other => panic!("expected UnknownMappingId, got {other:?}"),
        }
    }

    // R1 AC: unknown profile rejected before any processing.
    #[test]
    fn unknown_profile_rejected() {
        let mapping_store = MappingStore::new();
        let err = redact(
            "text",
            "bad_profile",
            RedactMode::Reversible,
            Some(&mapping_store),
        )
        .expect_err("unknown profile must error");
        assert!(
            matches!(err, RedactError::UnknownProfile { .. }),
            "error must be UnknownProfile, got: {err:?}"
        );
    }

    // R1 AC: reversible mode without a mapping_store → MappingStoreRequired.
    #[test]
    fn reversible_without_vault_errors() {
        let err = redact("alice@example.com", "default", RedactMode::Reversible, None)
            .expect_err("reversible without mapping_store must error");
        assert!(
            matches!(err, RedactError::MappingStoreRequired),
            "error must be MappingStoreRequired, got: {err:?}"
        );
    }

    // R1 AC: one-way mode produces no mapping_id and removes PII.
    #[test]
    fn one_way_mode_no_mapping_id() {
        let (redacted, mid) = redact(
            "Send to user@example.com.",
            "default",
            RedactMode::OneWay,
            None,
        )
        .unwrap();
        assert!(mid.is_none(), "one-way mode must not produce a mapping_id");
        assert!(
            !redacted.contains("user@example.com"),
            "PII must be removed"
        );
    }

    // ADR-0003 cross-call unlinkability: the SAME input in two independent
    // calls produces DIFFERENT tokens (fresh per-call salt), yet each call's
    // own mapping restores the original exactly. This is the property ADR-0001
    // claimed but did not deliver.
    #[test]
    fn cross_call_tokens_differ_but_each_round_trips() {
        let v1 = MappingStore::new();
        let v2 = MappingStore::new();
        let text = "From alice@example.com to bob@example.org.";
        let (r1, m1) = redact(text, "default", RedactMode::Reversible, Some(&v1)).unwrap();
        let (r2, m2) = redact(text, "default", RedactMode::Reversible, Some(&v2)).unwrap();

        assert_ne!(
            r1, r2,
            "per-call salt must make the same input redact to different tokens"
        );
        assert_eq!(unredact(&r1, &m1.unwrap(), &v1).unwrap(), text);
        assert_eq!(unredact(&r2, &m2.unwrap(), &v2).unwrap(), text);
    }

    // Two distinct emails in one call get two distinct tokens (both `Email`,
    // different discriminators), and the whole thing round-trips.
    #[test]
    fn distinct_values_distinct_tokens_and_round_trip() {
        let mapping_store = MappingStore::new();
        let text = "From alice@a.com to bob@b.com.";
        let (redacted, mid_opt) =
            redact(text, "pii", RedactMode::Reversible, Some(&mapping_store)).unwrap();
        let mid = mid_opt.unwrap();

        let toks = token::parse_tokens(&redacted);
        assert_eq!(toks.len(), 2, "two emails → two tokens");
        assert_eq!(toks[0].label, "Email");
        assert_eq!(toks[1].label, "Email");
        assert_ne!(
            toks[0].discriminator, toks[1].discriminator,
            "different values must get different discriminators"
        );
        assert_eq!(unredact(&redacted, &mid, &mapping_store).unwrap(), text);
    }

    // Same value repeated in one call collapses to one stable token, and all
    // occurrences restore.
    #[test]
    fn repeated_value_shares_one_token() {
        let mapping_store = MappingStore::new();
        let text = "a@x.com then a@x.com again.";
        let (redacted, mid_opt) =
            redact(text, "pii", RedactMode::Reversible, Some(&mapping_store)).unwrap();
        let toks = token::parse_tokens(&redacted);
        assert_eq!(toks.len(), 2, "two occurrences");
        assert_eq!(
            toks[0].as_token(),
            toks[1].as_token(),
            "same value → same token within a call"
        );
        assert_eq!(
            unredact(&redacted, &mid_opt.unwrap(), &mapping_store).unwrap(),
            text
        );
    }

    // MappingStore identifiers carry 128 unpredictable random bits.
    #[test]
    fn vault_id_format() {
        let mapping_store = MappingStore::new();
        let (_, mid0) = redact(
            "a@b.com",
            "default",
            RedactMode::Reversible,
            Some(&mapping_store),
        )
        .unwrap();
        let (_, mid1) = redact(
            "c@d.com",
            "default",
            RedactMode::Reversible,
            Some(&mapping_store),
        )
        .unwrap();
        let mid0 = mid0.unwrap();
        let mid1 = mid1.unwrap();
        assert_ne!(mid0, mid1);
        for id in [&mid0, &mid1] {
            assert!(id.starts_with("map_"));
            assert_eq!(id.len(), 36);
            assert!(id[4..].bytes().all(|b| b.is_ascii_hexdigit()));
        }
    }

    // The fixed salt used by the F3 conformance vectors (matches vectors.json).
    const TEST_SALT: [u8; token::SALT_LEN] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f,
    ];

    #[test]
    fn one_way_email_token() {
        let r = redact_to_mapping_with_salt("Contact alice@example.com for details.", &TEST_SALT);
        let toks = token::parse_tokens(&r.text);
        assert_eq!(toks.len(), 1);
        assert_eq!(toks[0].label, "Email");
        assert_eq!(r.tokens.len(), 1);
        assert_eq!(r.tokens[&toks[0].as_token()], "alice@example.com");
    }

    #[test]
    fn one_way_phone_dash() {
        let r = redact_to_mapping_with_salt("Call 555-867-5309 for support.", &TEST_SALT);
        let toks = token::parse_tokens(&r.text);
        assert_eq!(toks.len(), 1);
        assert_eq!(toks[0].label, "Phone");
        assert_eq!(r.tokens[&toks[0].as_token()], "555-867-5309");
    }

    #[test]
    fn one_way_ssn() {
        let r = redact_to_mapping_with_salt("Patient SSN is 123-45-6789.", &TEST_SALT);
        let toks = token::parse_tokens(&r.text);
        assert_eq!(toks.len(), 1);
        assert_eq!(toks[0].label, "Ssn");
        assert_eq!(r.tokens[&toks[0].as_token()], "123-45-6789");
    }

    #[test]
    fn one_way_clean_passthrough() {
        let text = "The quick brown fox jumps over the lazy dog.";
        let r = redact_one_way(text);
        assert_eq!(r.text, text);
        assert!(r.is_clean());
    }

    #[test]
    fn one_way_round_trip() {
        let input = "Forward to bob.smith@mail.corp.io now.";
        let r = redact_to_mapping(input);
        let restored = unredact_one_way(&r.text, &r.tokens).unwrap();
        assert_eq!(restored, input);
    }

    #[test]
    fn one_way_fixed_salt_is_reproducible() {
        // Same salt → identical bytes (the property the conformance vectors need).
        let a = redact_to_mapping_with_salt("mail me at a@b.com", &TEST_SALT);
        let b = redact_to_mapping_with_salt("mail me at a@b.com", &TEST_SALT);
        assert_eq!(a.text, b.text);
        assert_eq!(a.tokens, b.tokens);
    }

    #[test]
    fn one_way_random_salt_is_unlinkable() {
        // Default (random) salt → different tokens across calls, each restoring.
        let input = "mail me at a@b.com";
        let a = redact_to_mapping(input);
        let b = redact_to_mapping(input);
        assert_ne!(
            a.text, b.text,
            "random salt must vary the token across calls"
        );
        assert_eq!(unredact_one_way(&a.text, &a.tokens).unwrap(), input);
        assert_eq!(unredact_one_way(&b.text, &b.tokens).unwrap(), input);
    }

    #[test]
    fn one_way_repeated_value_shares_token() {
        let r = redact_to_mapping_with_salt("a@b.com and again a@b.com", &TEST_SALT);
        let toks = token::parse_tokens(&r.text);
        assert_eq!(toks.len(), 2);
        assert_eq!(toks[0].as_token(), toks[1].as_token());
        assert_eq!(r.tokens.len(), 1, "same value → one entry");
    }
    #[test]
    fn collision_extension_checks_every_candidate_including_full_digest() {
        let mut assigner = TokenAssigner::default();
        let digest = "a".repeat(64);
        let mut assigned = HashSet::new();
        for i in 0..20 {
            let original = format!("distinct-{i}");
            let token = assigner.assign_digest("Person", &original, &digest);
            assert!(
                assigned.insert(token.clone()),
                "collision must never reuse a token"
            );
            assert_eq!(assigner.assign_digest("Person", &original, &digest), token);
            assert_eq!(token::parse_tokens(&token).len(), 1);
        }
        assert!(
            assigned.iter().any(|token| token.len() > 73),
            "test must reach full-digest collision fallback"
        );
    }
}
