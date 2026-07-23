//! `ogentic-redact-core` — real-time, on-device sensitive-content redaction.
//!
//! This crate is the heart of the `ogentic-redact` library. It exposes the
//! primary [`redact`] and [`unredact`] entry points, along with the [`Vault`]
//! that stores reversible token mappings entirely on-device.
//!
//! # Quick start
//!
//! ```rust
//! use ogentic_redact_core::{Vault, RedactMode, redact, unredact};
//!
//! let vault = Vault::new();
//! let text = "Contact alice@example.com for details.";
//! let (redacted, mapping_id) = redact(text, "default", RedactMode::Reversible, Some(&vault))
//!     .expect("redact failed");
//! let id = mapping_id.expect("reversible mode must return a mapping_id");
//! let restored = unredact(&redacted, &id, &vault).expect("unredact failed");
//! assert_eq!(restored, text);
//! ```

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicU64, Ordering},
        Mutex,
    },
};

use thiserror::Error;

pub mod token;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors returned by [`redact`] and [`unredact`].
#[derive(Debug, Clone, Error)]
pub enum RedactError {
    /// The requested profile is not in the allow-list of known profiles.
    ///
    /// Unknown profiles are rejected before any processing occurs, mirroring
    /// the hostile-profile injection defence in `ogentic-shield`.
    #[error("unknown redaction profile: {profile:?}")]
    UnknownProfile {
        /// The name of the unrecognised profile.
        profile: String,
    },

    /// Reversible mode was requested but no vault reference was supplied.
    #[error("reversible mode requires a vault reference")]
    VaultRequired,

    /// The supplied `mapping_id` does not exist in the vault.
    #[error("unknown mapping id: {mapping_id:?}")]
    UnknownMappingId {
        /// The id that could not be resolved.
        mapping_id: String,
    },
}

// ---------------------------------------------------------------------------
// RedactMode
// ---------------------------------------------------------------------------

/// Controls whether redaction produces a reversible mapping or a one-way
/// substitution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedactMode {
    /// Store a token→original mapping in the vault and return a `mapping_id`.
    ///
    /// Requires `vault: Some(&vault)` in [`redact`]; returns
    /// [`RedactError::VaultRequired`] otherwise.
    Reversible,
    /// Replace entities with lossy tokens. No mapping is written and no
    /// `mapping_id` is returned.
    OneWay,
}

// ---------------------------------------------------------------------------
// Span
// ---------------------------------------------------------------------------

/// A detected entity span within the input text.
///
/// Offsets are byte offsets into the original `&str`.  Because entity
/// detection is currently limited to ASCII patterns (emails), byte offsets
/// always coincide with character boundaries.
#[derive(Debug, Clone)]
pub struct Span {
    /// Byte offset of the first byte of the entity (inclusive).
    pub start: usize,
    /// Byte offset one past the last byte of the entity (exclusive).
    pub end: usize,
    /// The entity-type label, e.g. `"EMAIL"`.
    pub entity_type: String,
}

// ---------------------------------------------------------------------------
// Vault
// ---------------------------------------------------------------------------

/// In-process, on-device store for reversible token mappings.
///
/// Each call to [`redact`] with [`RedactMode::Reversible`] produces a new
/// opaque `mapping_id` and stores a `token → original` table under that id.
/// [`unredact`] looks up the table by `mapping_id` to restore the original
/// text.
///
/// The vault survives only for the lifetime of the process (demo-design §5
/// option a — zero external dependencies, on-device by default). It is
/// `Send + Sync` and may be shared across threads.
#[derive(Debug, Default)]
pub struct Vault {
    mappings: Mutex<HashMap<String, HashMap<String, String>>>,
    counter: AtomicU64,
}

impl Vault {
    /// Create a new, empty vault.
    pub fn new() -> Self {
        Self::default()
    }

    /// Store a token→original mapping and return its fresh `mapping_id`.
    fn put(&self, mapping: HashMap<String, String>) -> String {
        let id = self.next_id();
        self.mappings
            .lock()
            .expect("vault mutex poisoned")
            .insert(id.clone(), mapping);
        id
    }

    /// Retrieve a clone of the mapping for `mapping_id`, or `None` if absent.
    fn get(&self, mapping_id: &str) -> Option<HashMap<String, String>> {
        self.mappings
            .lock()
            .expect("vault mutex poisoned")
            .get(mapping_id)
            .cloned()
    }

    fn next_id(&self) -> String {
        let n = self.counter.fetch_add(1, Ordering::Relaxed);
        format!("map_{n:016x}")
    }
}

// ---------------------------------------------------------------------------
// Known profiles
// ---------------------------------------------------------------------------

/// Profiles accepted by [`redact`]. Unknown profiles are rejected before any
/// processing, preventing hostile-profile injection.
const KNOWN_PROFILES: &[&str] = &["default", "pii", "phi"];

// ---------------------------------------------------------------------------
// Entity detection (stdlib-only placeholder)
// ---------------------------------------------------------------------------

/// Detect entities in `text` and return a deduplicated, sorted list of
/// [`Span`]s.
///
/// This is a minimal placeholder until `REDACT-INT-SHIELD` integration lands.
/// Currently detects: **EMAIL** (byte-scan for `@` with valid local-part and
/// domain).  Overlapping spans are removed, keeping the first match.
fn detect_entities(text: &str) -> Vec<Span> {
    let mut spans = Vec::new();
    detect_emails(text, &mut spans);
    spans.sort_by_key(|s| s.start);
    dedupe_spans(&mut spans);
    spans
}

/// Byte-scan for email addresses.
///
/// Heuristic: find `@`, extend leftward for a non-empty local-part (ASCII
/// alphanumeric + `.+-_`), extend rightward for a domain that contains at
/// least one `.`.  Placeholder for `REDACT-INT-SHIELD`.
fn detect_emails(text: &str, out: &mut Vec<Span>) {
    let bytes = text.as_bytes();
    for (at_pos, _) in bytes.iter().enumerate().filter(|(_, &b)| b == b'@') {
        // Extend leftward for local-part.
        let start = {
            let mut i = at_pos;
            while i > 0 && is_email_local_char(bytes[i - 1]) {
                i -= 1;
            }
            i
        };
        if start == at_pos {
            continue; // Empty local-part — not an email.
        }

        // Extend rightward for domain.
        let end = {
            let mut i = at_pos + 1;
            while i < bytes.len() && is_email_domain_char(bytes[i]) {
                i += 1;
            }
            i
        };
        let domain = &bytes[at_pos + 1..end];
        if domain.is_empty() || !domain.contains(&b'.') {
            continue; // Domain must have at least one dot.
        }

        out.push(Span {
            start,
            end,
            entity_type: "EMAIL".to_owned(),
        });
    }
}

fn is_email_local_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'.' | b'+' | b'-' | b'_')
}

fn is_email_domain_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-')
}

/// Remove overlapping spans in a sorted list, keeping the first match.
fn dedupe_spans(spans: &mut Vec<Span>) {
    let mut i = 0;
    while i + 1 < spans.len() {
        if spans[i].end > spans[i + 1].start {
            spans.remove(i + 1);
        } else {
            i += 1;
        }
    }
}

// ---------------------------------------------------------------------------
// Token helpers
// ---------------------------------------------------------------------------

/// Build the replacement token for a detected entity.
///
/// Format: `<<ENTITY_TYPE_N>>` (zero-indexed per type per document).
/// Example: `<<EMAIL_0>>`, `<<EMAIL_1>>`, `<<PERSON_0>>`.
fn make_token(entity_type: &str, index: usize) -> String {
    format!("<<{entity_type}_{index}>>")
}

/// Scan `text` for `<<…>>` redaction tokens.
///
/// Returns a list of `(byte_start, byte_end, token_name)` tuples where
/// `text[byte_start..byte_end]` is the full `<<TOKEN_NAME>>` pattern and
/// `token_name` is the content between the angle brackets.
fn scan_redaction_tokens(text: &str) -> Vec<(usize, usize, String)> {
    let mut result = Vec::new();
    let bytes = text.as_bytes();
    let mut i = 0;
    while i + 1 < bytes.len() {
        if bytes[i] == b'<' && bytes[i + 1] == b'<' {
            let outer_start = i;
            i += 2;
            let tok_start = i;
            // Scan for closing ">>"; abort on nested "<" (malformed token).
            while i + 1 < bytes.len() && !(bytes[i] == b'>' && bytes[i + 1] == b'>') {
                if bytes[i] == b'<' {
                    break; // Malformed — restart outer loop from current position.
                }
                i += 1;
            }
            if i + 1 < bytes.len() && bytes[i] == b'>' && bytes[i + 1] == b'>' {
                let tok_end = i;
                i += 2; // consume ">>"
                if let Ok(name) = std::str::from_utf8(&bytes[tok_start..tok_end]) {
                    result.push((outer_start, i, name.to_owned()));
                }
            }
            // If we broke out without finding ">>", i is already advanced; continue.
        } else {
            i += 1;
        }
    }
    result
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Redact sensitive entities in `text` using the named `profile`.
///
/// # Parameters
///
/// * `text`    — The input text to redact.
/// * `profile` — Must be one of `"default"`, `"pii"`, or `"phi"`.
/// * `mode`    — [`RedactMode::Reversible`] (vault-backed) or
///   [`RedactMode::OneWay`] (lossy, no mapping stored).
/// * `vault`   — Required when `mode` is [`RedactMode::Reversible`]; ignored
///   (and may be `None`) for [`RedactMode::OneWay`].
///
/// # Returns
///
/// `(redacted_text, mapping_id)` where `mapping_id` is `Some(id)` only for
/// reversible mode, and `None` for one-way mode.
///
/// # Errors
///
/// * [`RedactError::UnknownProfile`] — `profile` is not on the allow-list.
/// * [`RedactError::VaultRequired`]  — reversible mode requested without a
///   vault.
pub fn redact(
    text: &str,
    profile: &str,
    mode: RedactMode,
    vault: Option<&Vault>,
) -> Result<(String, Option<String>), RedactError> {
    // Gate 1: profile allow-list — reject before any processing.
    if !KNOWN_PROFILES.contains(&profile) {
        return Err(RedactError::UnknownProfile {
            profile: profile.to_owned(),
        });
    }

    // Gate 2: vault required for reversible mode.
    if mode == RedactMode::Reversible && vault.is_none() {
        return Err(RedactError::VaultRequired);
    }

    // Detect entities; assign zero-indexed tokens per entity type.
    let spans = detect_entities(text);
    let mut type_counts: HashMap<&str, usize> = HashMap::new();
    let tokens: Vec<(&Span, String)> = spans
        .iter()
        .map(|span| {
            let idx = type_counts.entry(span.entity_type.as_str()).or_insert(0);
            let token = make_token(&span.entity_type, *idx);
            *idx += 1;
            (span, token)
        })
        .collect();

    // Splice the redacted string.
    let mut redacted = String::with_capacity(text.len());
    let mut cursor = 0usize;
    for (span, token) in &tokens {
        redacted.push_str(&text[cursor..span.start]);
        redacted.push_str(token);
        cursor = span.end;
    }
    redacted.push_str(&text[cursor..]);

    // Reversible path: write token→original map to vault.
    if mode == RedactMode::Reversible {
        let mapping: HashMap<String, String> = tokens
            .iter()
            .map(|(span, token)| (token.clone(), text[span.start..span.end].to_owned()))
            .collect();
        // Safety: VaultRequired guard above ensures vault is Some here.
        let id = vault
            .expect("vault required; already checked above")
            .put(mapping);
        return Ok((redacted, Some(id)));
    }

    Ok((redacted, None))
}

/// Restore the original text from a redacted string using a vault mapping.
///
/// Tokens found in `text` that are **not** present in the mapping identified
/// by `mapping_id` are left untouched — this is documented behaviour, not an
/// error.  Only the mapping for the exact `mapping_id` is consulted; there is
/// no cross-mapping resolution.
///
/// # Errors
///
/// * [`RedactError::UnknownMappingId`] — `mapping_id` is not in the vault.
pub fn unredact(text: &str, mapping_id: &str, vault: &Vault) -> Result<String, RedactError> {
    let mapping = vault
        .get(mapping_id)
        .ok_or_else(|| RedactError::UnknownMappingId {
            mapping_id: mapping_id.to_owned(),
        })?;

    let positions = scan_redaction_tokens(text);
    if positions.is_empty() {
        return Ok(text.to_owned());
    }

    let mut restored = String::with_capacity(text.len());
    let mut cursor = 0usize;

    for (start, end, token_name) in &positions {
        restored.push_str(&text[cursor..*start]);

        let full_token = format!("<<{token_name}>>");
        if let Some(original) = mapping.get(&full_token) {
            restored.push_str(original);
        } else {
            // Token not in this mapping — leave it verbatim (documented behaviour).
            restored.push_str(&text[*start..*end]);
        }
        cursor = *end;
    }

    restored.push_str(&text[cursor..]);
    Ok(restored)
}

// ---------------------------------------------------------------------------
// redact_one_way — cross-language conformance API (F3)
// ---------------------------------------------------------------------------

/// The result of a [`redact_one_way`] call.
///
/// `text` is the redacted string; `tokens` maps each numbered placeholder back
/// to the original value.  Serialises to the same JSON shape as the C FFI
/// (`{"text": "…", "tokens": {…}}`), so all four binding surfaces produce
/// byte-identical output when driven by the same input.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RedactOneWayResult {
    /// Redacted text, e.g. `"Contact [EMAIL_1] at [PHONE_1]."`.
    pub text: String,
    /// Token→original map, e.g. `{"[EMAIL_1]": "alice@example.com"}`.
    pub tokens: HashMap<String, String>,
}

impl RedactOneWayResult {
    /// `true` when no PII was detected.
    pub fn is_clean(&self) -> bool {
        self.tokens.is_empty()
    }
}

/// Redact PII in `text` with deterministic numbered placeholder tokens.
///
/// This is the function used by the F3 cross-language conformance test.  All
/// four surfaces (Rust native, Python via PyO3, Node via napi-rs, Swift via C
/// FFI) delegate to this implementation and must produce byte-identical output
/// for the same input.
///
/// Token format: `[EMAIL_N]`, `[PHONE_N]`, `[SSN_N]` (1-indexed, left-to-right).
///
/// Detected patterns: email address, US phone number, US Social Security Number.
pub fn redact_one_way(text: &str) -> RedactOneWayResult {
    let (out_text, tokens) = redact_one_way_inner(text);
    RedactOneWayResult {
        text: out_text,
        tokens,
    }
}

/// Restore redacted placeholders using the token map from a prior
/// [`redact_one_way`] call.
pub fn unredact_one_way(redacted: &str, tokens: &HashMap<String, String>) -> String {
    let mut result = redacted.to_owned();
    for (placeholder, original) in tokens {
        result = result.replace(placeholder.as_str(), original.as_str());
    }
    result
}

// ── Internal: byte-level pattern matching ─────────────────────────────────────

fn redact_one_way_inner(text: &str) -> (String, HashMap<String, String>) {
    let mut out = String::with_capacity(text.len());
    let mut token_map: HashMap<String, String> = HashMap::new();
    let mut email_n: u32 = 0;
    let mut phone_n: u32 = 0;
    let mut ssn_n: u32 = 0;

    let bytes = text.as_bytes();
    let len = bytes.len();
    let mut i = 0;

    while i < len {
        if let Some((matched, end)) = match_email(bytes, i) {
            email_n += 1;
            let tok = format!("[EMAIL_{email_n}]");
            token_map.insert(tok.clone(), matched);
            out.push_str(&tok);
            i = end;
            continue;
        }
        if let Some((matched, end)) = match_ssn(bytes, i) {
            ssn_n += 1;
            let tok = format!("[SSN_{ssn_n}]");
            token_map.insert(tok.clone(), matched);
            out.push_str(&tok);
            i = end;
            continue;
        }
        if let Some((matched, end)) = match_phone(bytes, i) {
            phone_n += 1;
            let tok = format!("[PHONE_{phone_n}]");
            token_map.insert(tok.clone(), matched);
            out.push_str(&tok);
            i = end;
            continue;
        }
        // Pass through, preserving multi-byte UTF-8 sequences.
        if bytes[i].is_ascii() {
            out.push(char::from(bytes[i]));
            i += 1;
        } else {
            let tail = &text[i..];
            let c = tail.chars().next().unwrap_or('\u{FFFD}');
            out.push(c);
            i += c.len_utf8();
        }
    }

    (out, token_map)
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // AC1: round-trip — redact → unredact → original text restored exactly.
    #[test]
    fn round_trip_restores_original() {
        let vault = Vault::new();
        let text = "Contact alice@example.com for support.";
        let (redacted, mid_opt) =
            redact(text, "default", RedactMode::Reversible, Some(&vault)).unwrap();
        let mid = mid_opt.expect("reversible mode must produce a mapping_id");

        assert!(
            redacted.contains("<<EMAIL_0>>"),
            "redacted text must contain the token"
        );
        assert!(
            !redacted.contains("alice@example.com"),
            "PII must not appear in redacted output"
        );

        let restored = unredact(&redacted, &mid, &vault).unwrap();
        assert_eq!(
            restored, text,
            "round-trip must restore original text exactly"
        );
    }

    // AC2: unknown mapping_id → RedactError::UnknownMappingId (sanitised error).
    #[test]
    fn unknown_mapping_id_returns_domain_error() {
        let vault = Vault::new();
        let err = unredact("<<EMAIL_0>>", "map_0000000000000000", &vault)
            .expect_err("unknown mapping_id must produce an error");
        assert!(
            matches!(err, RedactError::UnknownMappingId { .. }),
            "error must be UnknownMappingId, got: {err:?}"
        );
    }

    // AC3: tokens absent from the vault mapping are left untouched.
    #[test]
    fn unknown_token_left_untouched() {
        let vault = Vault::new();
        let text = "Hello alice@example.com!";
        let (redacted, mid_opt) =
            redact(text, "default", RedactMode::Reversible, Some(&vault)).unwrap();
        let mid = mid_opt.unwrap();

        // Inject a token that was NOT in the original redacted text.
        let with_foreign = format!("{redacted} and <<PERSON_0>>");
        let restored = unredact(&with_foreign, &mid, &vault).unwrap();

        assert!(
            restored.contains("<<PERSON_0>>"),
            "foreign token must remain verbatim"
        );
        assert!(
            restored.contains("alice@example.com"),
            "known token must be restored"
        );
    }

    // AC4: no cross-mapping bleed — mapping scope is strictly isolated per mapping_id.
    //
    // Both mappings produce <<EMAIL_0>> as the token, but each mapping_id points to
    // a different sub-map in the vault.  Unredacting mapping A's text with mapping B's
    // id yields mapping B's value (not mapping A's original), demonstrating that the
    // lookup is scoped to the specified mapping_id only.
    #[test]
    fn no_cross_mapping_bleed() {
        let vault = Vault::new();
        let text_a = "Contact alice@example.com.";
        let text_b = "Reach out to bob@example.org.";

        let (redacted_a, mid_a_opt) =
            redact(text_a, "default", RedactMode::Reversible, Some(&vault)).unwrap();
        let (_redacted_b, mid_b_opt) =
            redact(text_b, "default", RedactMode::Reversible, Some(&vault)).unwrap();
        let mid_a = mid_a_opt.unwrap();
        let mid_b = mid_b_opt.unwrap();

        // Mapping ids must be distinct.
        assert_ne!(mid_a, mid_b);

        // Correct mapping restores correctly.
        let restored_a = unredact(&redacted_a, &mid_a, &vault).unwrap();
        assert_eq!(restored_a, text_a, "correct mapping must restore original");

        // Using mapping B's id to unredact mapping A's text must NOT restore text_a's
        // original — it resolves the token via mapping B's sub-map only.
        let cross = unredact(&redacted_a, &mid_b, &vault).unwrap();
        assert_ne!(
            cross, text_a,
            "wrong mapping_id must not restore correct original — proves isolation"
        );
        // Mapping B maps <<EMAIL_0>> to bob@example.org, so alice must not appear.
        assert!(
            !cross.contains("alice@example.com"),
            "alice's PII must not appear when using mapping B"
        );
    }

    // AC5: failure-path for missing/expired mapping_id.
    #[test]
    fn missing_mapping_id_returns_error() {
        let vault = Vault::new();
        let result = unredact("text with <<EMAIL_0>>", "map_does_not_exist", &vault);
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
        let vault = Vault::new();
        let err = redact("text", "bad_profile", RedactMode::Reversible, Some(&vault))
            .expect_err("unknown profile must error");
        assert!(
            matches!(err, RedactError::UnknownProfile { .. }),
            "error must be UnknownProfile, got: {err:?}"
        );
    }

    // R1 AC: reversible mode without a vault → VaultRequired.
    #[test]
    fn reversible_without_vault_errors() {
        let err = redact("alice@example.com", "default", RedactMode::Reversible, None)
            .expect_err("reversible without vault must error");
        assert!(
            matches!(err, RedactError::VaultRequired),
            "error must be VaultRequired, got: {err:?}"
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

    // R1 AC: determinism — same input + same profile → identical redacted output.
    #[test]
    fn determinism_same_input_same_output() {
        let v1 = Vault::new();
        let v2 = Vault::new();
        let text = "From alice@example.com to bob@example.org.";
        let (r1, _) = redact(text, "default", RedactMode::Reversible, Some(&v1)).unwrap();
        let (r2, _) = redact(text, "default", RedactMode::Reversible, Some(&v2)).unwrap();
        assert_eq!(r1, r2, "same input must produce identical redacted output");
    }

    // Multiple emails: indexed as EMAIL_0, EMAIL_1, … and full round-trip.
    #[test]
    fn multiple_emails_indexed_and_round_trip() {
        let vault = Vault::new();
        let text = "From alice@a.com to bob@b.com.";
        let (redacted, mid_opt) =
            redact(text, "pii", RedactMode::Reversible, Some(&vault)).unwrap();
        let mid = mid_opt.unwrap();
        assert!(redacted.contains("<<EMAIL_0>>"));
        assert!(redacted.contains("<<EMAIL_1>>"));
        let restored = unredact(&redacted, &mid, &vault).unwrap();
        assert_eq!(restored, text);
    }

    // Vault id format: "map_{n:016x}".
    #[test]
    fn vault_id_format() {
        let vault = Vault::new();
        let (_, mid0) = redact("a@b.com", "default", RedactMode::Reversible, Some(&vault)).unwrap();
        let (_, mid1) = redact("c@d.com", "default", RedactMode::Reversible, Some(&vault)).unwrap();
        assert_eq!(mid0.unwrap(), "map_0000000000000000");
        assert_eq!(mid1.unwrap(), "map_0000000000000001");
    }

    // F3 conformance: redact_one_way produces [EMAIL_N] tokens.
    #[test]
    fn one_way_email_token() {
        let r = redact_one_way("Contact alice@example.com for details.");
        assert_eq!(r.text, "Contact [EMAIL_1] for details.");
        assert_eq!(r.tokens["[EMAIL_1]"], "alice@example.com");
        assert!(r.tokens.len() == 1);
    }

    #[test]
    fn one_way_phone_dash() {
        let r = redact_one_way("Call 555-867-5309 for support.");
        assert_eq!(r.text, "Call [PHONE_1] for support.");
        assert_eq!(r.tokens["[PHONE_1]"], "555-867-5309");
    }

    #[test]
    fn one_way_ssn() {
        let r = redact_one_way("Patient SSN is 123-45-6789.");
        assert_eq!(r.text, "Patient SSN is [SSN_1].");
        assert_eq!(r.tokens["[SSN_1]"], "123-45-6789");
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
        let r = redact_one_way(input);
        let restored = unredact_one_way(&r.text, &r.tokens);
        assert_eq!(restored, input);
    }
}
