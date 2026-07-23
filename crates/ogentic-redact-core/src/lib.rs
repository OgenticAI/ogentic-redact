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
    mappings: Mutex<HashMap<String, VaultRecord>>,
    counter: AtomicU64,
}

/// One reversible redaction call's worth of vault state (ADR-0003 §3).
///
/// Holds the per-call `call_salt` (so tokens are reproducible/auditable) plus,
/// for each emitted token, the exact original and the `label`/`canonical`
/// grouping form it was derived from.
#[derive(Debug, Clone)]
struct VaultRecord {
    #[allow(dead_code)] // retained for auditing / future vault-export (OGE-1243)
    call_salt: [u8; token::SALT_LEN],
    entries: HashMap<String, VaultEntry>,
}

/// A single token→original mapping within a [`VaultRecord`].
#[derive(Debug, Clone)]
struct VaultEntry {
    original: String,
    #[allow(dead_code)] // retained for auditing / future vault-export (OGE-1243)
    label: String,
    #[allow(dead_code)]
    canonical: String,
}

impl Vault {
    /// Create a new, empty vault.
    pub fn new() -> Self {
        Self::default()
    }

    /// Store a redaction record and return its fresh `mapping_id`.
    fn put(&self, record: VaultRecord) -> String {
        let id = self.next_id();
        self.mappings
            .lock()
            .expect("vault mutex poisoned")
            .insert(id.clone(), record);
        id
    }

    /// Retrieve a clone of the record for `mapping_id`, or `None` if absent.
    fn get(&self, mapping_id: &str) -> Option<VaultRecord> {
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
// Token assignment (ADR-0003 grammar via the `token` module)
// ---------------------------------------------------------------------------

/// Assign a `[Label_<salted-hex>]` token to every span under one `call_salt`.
///
/// Guarantees within-call stability (same `(label, canonical)` → same token)
/// and resolves the rare within-call discriminator collision by extending that
/// token to a longer hex (ADR-0003 §4). Returns the per-span tokens in span
/// order plus the token→entry table for the vault.
fn assign_tokens<'a>(
    text: &'a str,
    spans: &'a [Span],
    call_salt: &[u8; token::SALT_LEN],
) -> (Vec<(&'a Span, String)>, HashMap<String, VaultEntry>) {
    let mut per_span: Vec<(&Span, String)> = Vec::with_capacity(spans.len());
    let mut entries: HashMap<String, VaultEntry> = HashMap::new();
    let mut assigner = TokenAssigner::default();

    for span in spans {
        let original = &text[span.start..span.end];
        let label = token::label_for(&span.entity_type);
        let canonical = token::canonicalize(original);
        let tok = assigner.assign(&label, &canonical, call_salt);
        entries.entry(tok.clone()).or_insert_with(|| VaultEntry {
            original: original.to_owned(),
            label,
            canonical,
        });
        per_span.push((span, tok));
    }

    (per_span, entries)
}

/// Assigns `[Label_<salted-hex>]` tokens within a single call, guaranteeing
/// within-call stability (same `(label, canonical)` → same token) and
/// resolving discriminator collisions by extending to a longer hex
/// (ADR-0003 §4). Shared by the reversible ([`assign_tokens`]) and one-way
/// ([`redact_one_way_inner`]) paths.
#[derive(Default)]
struct TokenAssigner {
    /// (label, canonical) → token, for stability.
    seen: HashMap<(String, String), String>,
    /// token → canonical, for collision detection.
    token_canon: HashMap<String, String>,
}

impl TokenAssigner {
    fn assign(&mut self, label: &str, canonical: &str, call_salt: &[u8]) -> String {
        let key = (label.to_owned(), canonical.to_owned());
        if let Some(existing) = self.seen.get(&key) {
            return existing.clone();
        }
        let short = token::discriminator(call_salt, label, canonical);
        let candidate = token::emit(label, &short);
        let tok = match self.token_canon.get(&candidate) {
            None => candidate,
            Some(c) if c == canonical => candidate,
            // Genuine collision: two different values, same 8-hex → extend to 12.
            Some(_) => {
                let full = token::full_discriminator(call_salt, label, canonical);
                token::emit(label, &full[..token::DISCRIMINATOR_LEN_EXTENDED])
            },
        };
        self.seen.insert(key, tok.clone());
        self.token_canon.insert(tok.clone(), canonical.to_owned());
        tok
    }
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

    // Fresh per-call salt: the discriminator derives from it, so the same value
    // yields a different token in a different call (ADR-0003 §3).
    let call_salt: [u8; token::SALT_LEN] = rand::random();

    let spans = detect_entities(text);
    let (per_span, entries) = assign_tokens(text, &spans, &call_salt);

    // Splice the redacted string.
    let mut redacted = String::with_capacity(text.len());
    let mut cursor = 0usize;
    for (span, tok) in &per_span {
        redacted.push_str(&text[cursor..span.start]);
        redacted.push_str(tok);
        cursor = span.end;
    }
    redacted.push_str(&text[cursor..]);

    // Reversible path: persist the record (salt + entries) to the vault.
    // One-way path emits the same salted grammar but keeps no mapping.
    if mode == RedactMode::Reversible {
        // Safety: VaultRequired guard above ensures vault is Some here.
        let id = vault
            .expect("vault required; already checked above")
            .put(VaultRecord { call_salt, entries });
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
    let record = vault
        .get(mapping_id)
        .ok_or_else(|| RedactError::UnknownMappingId {
            mapping_id: mapping_id.to_owned(),
        })?;

    let positions = token::parse_tokens(text);
    if positions.is_empty() {
        return Ok(text.to_owned());
    }

    let mut restored = String::with_capacity(text.len());
    let mut cursor = 0usize;

    for tok in &positions {
        restored.push_str(&text[cursor..tok.start]);

        if let Some(entry) = record.entries.get(&tok.as_token()) {
            restored.push_str(&entry.original);
        } else {
            // Parsed a token shape not in this mapping — leave it verbatim
            // (documented behaviour; no cross-mapping resolution).
            restored.push_str(&text[tok.start..tok.end]);
        }
        cursor = tok.end;
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
    /// Redacted text, e.g. `"Contact [Email_3f8a2c1b] at [Phone_9be10422]."`.
    pub text: String,
    /// Token→original map, e.g. `{"[Email_3f8a2c1b]": "alice@example.com"}`.
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
/// Token format: `[Label_<salted-hex>]` (ADR-0003), e.g. `[Email_3f8a2c1b]`.
/// A fresh per-call salt makes the same value redact differently across calls;
/// use [`redact_one_way_with_salt`] to supply a fixed salt (conformance / tests).
///
/// Detected patterns: email address, US phone number, US Social Security Number.
/// (Detection is a documented dev convenience — production spans come from
/// Shield, per ADR-0002.)
pub fn redact_one_way(text: &str) -> RedactOneWayResult {
    let call_salt: [u8; token::SALT_LEN] = rand::random();
    redact_one_way_with_salt(text, &call_salt)
}

/// [`redact_one_way`] with an explicit `call_salt`, so output is reproducible.
///
/// The salt need not be [`token::SALT_LEN`] bytes — HMAC accepts any key — but
/// callers that want cross-surface byte-identity must agree on the exact bytes
/// (this is how the F3 conformance vectors stay deterministic).
pub fn redact_one_way_with_salt(text: &str, call_salt: &[u8]) -> RedactOneWayResult {
    let (out_text, tokens) = redact_one_way_inner(text, call_salt);
    RedactOneWayResult {
        text: out_text,
        tokens,
    }
}

/// Restore redacted placeholders using the token map from a prior
/// [`redact_one_way`] call.
///
/// Scans for `[Label_<hex>]` tokens and replaces each by exact map lookup
/// (ADR-0003 §7) — never a blind substring replace, so one token's bytes being
/// a substring of another's cannot cause a double substitution.
pub fn unredact_one_way(redacted: &str, tokens: &HashMap<String, String>) -> String {
    let positions = token::parse_tokens(redacted);
    if positions.is_empty() {
        return redacted.to_owned();
    }
    let mut out = String::with_capacity(redacted.len());
    let mut cursor = 0usize;
    for tok in &positions {
        out.push_str(&redacted[cursor..tok.start]);
        match tokens.get(&tok.as_token()) {
            Some(original) => out.push_str(original),
            None => out.push_str(&redacted[tok.start..tok.end]),
        }
        cursor = tok.end;
    }
    out.push_str(&redacted[cursor..]);
    out
}

// ── Internal: byte-level pattern matching ─────────────────────────────────────

fn redact_one_way_inner(text: &str, call_salt: &[u8]) -> (String, HashMap<String, String>) {
    let mut out = String::with_capacity(text.len());
    let mut token_map: HashMap<String, String> = HashMap::new();
    let mut assigner = TokenAssigner::default();

    let bytes = text.as_bytes();
    let len = bytes.len();
    let mut i = 0;

    while i < len {
        // Detection order is significant: email, then SSN, then phone.
        let hit = match_email(bytes, i)
            .map(|(m, e)| ("EMAIL", m, e))
            .or_else(|| match_ssn(bytes, i).map(|(m, e)| ("SSN", m, e)))
            .or_else(|| match_phone(bytes, i).map(|(m, e)| ("PHONE", m, e)));

        if let Some((entity_type, matched, end)) = hit {
            let label = token::label_for(entity_type);
            let canonical = token::canonicalize(&matched);
            let tok = assigner.assign(&label, &canonical, call_salt);
            token_map.entry(tok.clone()).or_insert(matched);
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

        let toks = token::parse_tokens(&redacted);
        assert_eq!(toks.len(), 1, "one email → one token");
        assert_eq!(toks[0].label, "Email", "token must carry the Email label");
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
        let err = unredact("[Email_deadbeef]", "map_0000000000000000", &vault)
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

        // Inject a valid-grammar token that was NOT in this mapping.
        let with_foreign = format!("{redacted} and [Person_deadbeef]");
        let restored = unredact(&with_foreign, &mid, &vault).unwrap();

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
        let result = unredact("text with [Email_deadbeef]", "map_does_not_exist", &vault);
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

    // ADR-0003 cross-call unlinkability: the SAME input in two independent
    // calls produces DIFFERENT tokens (fresh per-call salt), yet each call's
    // own mapping restores the original exactly. This is the property ADR-0001
    // claimed but did not deliver.
    #[test]
    fn cross_call_tokens_differ_but_each_round_trips() {
        let v1 = Vault::new();
        let v2 = Vault::new();
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
        let vault = Vault::new();
        let text = "From alice@a.com to bob@b.com.";
        let (redacted, mid_opt) =
            redact(text, "pii", RedactMode::Reversible, Some(&vault)).unwrap();
        let mid = mid_opt.unwrap();

        let toks = token::parse_tokens(&redacted);
        assert_eq!(toks.len(), 2, "two emails → two tokens");
        assert_eq!(toks[0].label, "Email");
        assert_eq!(toks[1].label, "Email");
        assert_ne!(
            toks[0].discriminator, toks[1].discriminator,
            "different values must get different discriminators"
        );
        assert_eq!(unredact(&redacted, &mid, &vault).unwrap(), text);
    }

    // Same value repeated in one call collapses to one stable token, and all
    // occurrences restore.
    #[test]
    fn repeated_value_shares_one_token() {
        let vault = Vault::new();
        let text = "a@x.com then a@x.com again.";
        let (redacted, mid_opt) =
            redact(text, "pii", RedactMode::Reversible, Some(&vault)).unwrap();
        let toks = token::parse_tokens(&redacted);
        assert_eq!(toks.len(), 2, "two occurrences");
        assert_eq!(
            toks[0].as_token(),
            toks[1].as_token(),
            "same value → same token within a call"
        );
        assert_eq!(
            unredact(&redacted, &mid_opt.unwrap(), &vault).unwrap(),
            text
        );
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

    // The fixed salt used by the F3 conformance vectors (matches vectors.json).
    const TEST_SALT: [u8; token::SALT_LEN] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f,
    ];

    #[test]
    fn one_way_email_token() {
        let r = redact_one_way_with_salt("Contact alice@example.com for details.", &TEST_SALT);
        let toks = token::parse_tokens(&r.text);
        assert_eq!(toks.len(), 1);
        assert_eq!(toks[0].label, "Email");
        assert_eq!(r.tokens.len(), 1);
        assert_eq!(r.tokens[&toks[0].as_token()], "alice@example.com");
    }

    #[test]
    fn one_way_phone_dash() {
        let r = redact_one_way_with_salt("Call 555-867-5309 for support.", &TEST_SALT);
        let toks = token::parse_tokens(&r.text);
        assert_eq!(toks.len(), 1);
        assert_eq!(toks[0].label, "Phone");
        assert_eq!(r.tokens[&toks[0].as_token()], "555-867-5309");
    }

    #[test]
    fn one_way_ssn() {
        let r = redact_one_way_with_salt("Patient SSN is 123-45-6789.", &TEST_SALT);
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
        let r = redact_one_way(input);
        let restored = unredact_one_way(&r.text, &r.tokens);
        assert_eq!(restored, input);
    }

    #[test]
    fn one_way_fixed_salt_is_reproducible() {
        // Same salt → identical bytes (the property the conformance vectors need).
        let a = redact_one_way_with_salt("mail me at a@b.com", &TEST_SALT);
        let b = redact_one_way_with_salt("mail me at a@b.com", &TEST_SALT);
        assert_eq!(a.text, b.text);
        assert_eq!(a.tokens, b.tokens);
    }

    #[test]
    fn one_way_random_salt_is_unlinkable() {
        // Default (random) salt → different tokens across calls, each restoring.
        let input = "mail me at a@b.com";
        let a = redact_one_way(input);
        let b = redact_one_way(input);
        assert_ne!(
            a.text, b.text,
            "random salt must vary the token across calls"
        );
        assert_eq!(unredact_one_way(&a.text, &a.tokens), input);
        assert_eq!(unredact_one_way(&b.text, &b.tokens), input);
    }

    #[test]
    fn one_way_repeated_value_shares_token() {
        let r = redact_one_way_with_salt("a@b.com and again a@b.com", &TEST_SALT);
        let toks = token::parse_tokens(&r.text);
        assert_eq!(toks.len(), 2);
        assert_eq!(toks[0].as_token(), toks[1].as_token());
        assert_eq!(r.tokens.len(), 1, "same value → one entry");
    }
}
