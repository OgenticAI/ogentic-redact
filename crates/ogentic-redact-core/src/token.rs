//! Token grammar per [ADR-0003](../../../docs/adr/0003-ecosystem-token-grammar.md).
//!
//! Native token grammar: `[Label_<salted-hex>]`, aligned to the
//! published `ogentic-shield` shape (e.g. `[Email_3f8a2c1b]`).
//!
//! * `label` — CamelCase, no underscore. Mapped from a Shield category string
//!   (`EMAIL_ADDRESS` → `Email`) via [`label_for`].
//! * `discriminator` — the first 8 lowercase-hex chars of
//!   `HMAC-SHA256(call_salt, label ":" original_value)`. Because the salt is
//!   fresh per call and reaches the emitted token, the same value yields a
//!   different token across calls (cross-call unlinkability), while the same
//!   `(label, original_value)` within one call yields the same token.
//!
//! The label carries no `_`, so the single `_` before the hex is always the
//! separator and parsing is unambiguous ([`parse_tokens`]).

use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Number of random bytes in a per-call salt.
pub const SALT_LEN: usize = 16;

/// Default discriminator length in hex chars (32 bits).
pub const DISCRIMINATOR_LEN: usize = 8;

/// First extended discriminator length on within-call collision (48 bits).
/// Further collisions extend again until the token is unique.
pub const DISCRIMINATOR_LEN_EXTENDED: usize = 12;

/// The fixed label used by opaque mode, hiding the entity category.
pub const OPAQUE_LABEL: &str = "Redacted";

/// Canonical (label, entity-types) table — the shared source of truth for
/// mapping a Shield category string to a token label.
///
/// Mirrors `ogentic-shield`'s `CATEGORY_LABEL_TO_ENTITY_TYPES`
/// (`src/ogentic_shield/redaction.py`). The mapping is many-to-one: several
/// entity types collapse to one coarser label (e.g. `EXECUTIVE_NAME` →
/// `Person`), which reduces category leakage. The token displays only this
/// coarse label; the mapping stores the exact original value.
///
/// Kept in sync with `conformance/category-labels.json` by a parity test.
const LABEL_TABLE: &[(&str, &[&str])] = &[
    (
        "Person",
        &["PERSON", "EXECUTIVE_NAME", "PATIENT_NAME", "PROVIDER_NAME"],
    ),
    ("Address", &["LOCATION"]),
    (
        "Sponsor",
        &["INSTITUTION_NAME", "LAW_FIRM_NAME", "FUND_INFORMATION"],
    ),
    ("Email", &["EMAIL_ADDRESS"]),
    ("Phone", &["PHONE_NUMBER"]),
    ("Ssn", &["SSN", "US_SSN"]),
    ("DateOfBirth", &["DATE_OF_BIRTH"]),
    ("InsuranceId", &["INSURANCE_ID"]),
    ("MedicalLicense", &["MEDICAL_LICENSE"]),
    ("CaseNumber", &["CASE_NUMBER"]),
    ("BatesNumber", &["BATES_NUMBER"]),
    ("Diagnosis", &["DIAGNOSIS_CODE"]),
    ("Medication", &["MEDICATION"]),
    ("CreditCard", &["CREDIT_CARD"]),
    ("BankNumber", &["US_BANK_NUMBER"]),
    ("Url", &["URL"]),
    ("IpAddress", &["IP_ADDRESS"]),
    ("Passport", &["US_PASSPORT"]),
    ("Itin", &["US_ITIN"]),
    ("DriverLicense", &["US_DRIVER_LICENSE"]),
    ("DateTime", &["DATE_TIME"]),
    ("Iban", &["IBAN_CODE"]),
    ("Nationality", &["NRP"]),
];

/// Map a Shield category / entity-type string to its token label.
///
/// Known entity types resolve through the internal `LABEL_TABLE`; anything else falls back
/// to `ASCII title-case with separators removed` (`COUNSEL_COMMUNICATION` →
/// `CounselCommunication`). Custom labels are capped at 32 ASCII letters and
/// use `Redacted` when no letters remain, so every emitted label is parseable.
pub fn label_for(entity_type: &str) -> String {
    for (label, types) in LABEL_TABLE {
        if types.contains(&entity_type) {
            return (*label).to_owned();
        }
    }
    fallback_label(entity_type)
}

/// Encode custom categories into the bounded ASCII label grammar.
/// Unsupported characters separate words; empty encodings use `Redacted`.
fn fallback_label(entity_type: &str) -> String {
    let mut out = String::new();
    for part in entity_type
        .split(|c: char| !c.is_ascii_alphabetic())
        .filter(|p| !p.is_empty())
    {
        let mut chars = part.chars();
        if let Some(first) = chars.next() {
            out.push(first.to_ascii_uppercase());
            out.extend(chars.map(|c| c.to_ascii_lowercase()));
        }
    }
    out.truncate(32);
    if out.is_empty() {
        OPAQUE_LABEL.to_owned()
    } else {
        out
    }
}

/// Normalize a value into its grouping form: collapse runs of Unicode whitespace
/// to a single space, trim, and lowercase. This is an optional grouping utility;
/// token identity uses exact originals so case and spacing restore losslessly.
pub fn canonicalize(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut prev_ws = false;
    for c in value.trim().chars() {
        if c.is_whitespace() {
            if !prev_ws {
                out.push(' ');
                prev_ws = true;
            }
        } else {
            for lc in c.to_lowercase() {
                out.push(lc);
            }
            prev_ws = false;
        }
    }
    out
}

/// Compute the full 64-hex HMAC-SHA256 of `label ":" original_value` under
/// `call_salt`. Callers truncate to [`DISCRIMINATOR_LEN`] (extending on
/// collision); the full digest is exposed so a caller can extend deterministically.
pub fn full_discriminator(call_salt: &[u8], label: &str, original_value: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(call_salt).expect("HMAC accepts keys of any length");
    mac.update(label.as_bytes());
    mac.update(b":");
    mac.update(original_value.as_bytes());
    to_hex(&mac.finalize().into_bytes())
}

/// The default-length (8-hex) discriminator for `(label, original_value)`.
pub fn discriminator(call_salt: &[u8], label: &str, original_value: &str) -> String {
    let mut disc = full_discriminator(call_salt, label, original_value);
    disc.truncate(DISCRIMINATOR_LEN);
    disc
}

/// Emit a token from a label and an already-computed discriminator.
pub fn emit(label: &str, discriminator: &str) -> String {
    format!("[{label}_{discriminator}]")
}

/// A token located in text: byte range plus its parsed label and discriminator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedToken {
    /// Byte offset of the opening `[` (inclusive).
    pub start: usize,
    /// Byte offset one past the closing `]` (exclusive).
    pub end: usize,
    /// The CamelCase label between `[` and `_`.
    pub label: String,
    /// The lowercase-hex discriminator between `_` and `]`.
    pub discriminator: String,
}

impl ParsedToken {
    /// Reconstruct the exact token string, `[Label_disc]`.
    pub fn as_token(&self) -> String {
        emit(&self.label, &self.discriminator)
    }
}

/// Scan `text` for every `[Label_<hex>]` token, left to right, non-overlapping.
///
/// A token is `[`, a label `[A-Z][A-Za-z]{0,31}`, `_`, a discriminator of at least
/// [`DISCRIMINATOR_LEN`] lowercase-hex chars, `]`. Runs that do not match the
/// grammar exactly (wrong case, spaces, too-short hex) are ignored, so ordinary
/// bracketed prose is not mistaken for a token.
pub fn parse_tokens(text: &str) -> Vec<ParsedToken> {
    let bytes = text.as_bytes();
    let len = bytes.len();
    let mut out = Vec::new();
    let mut i = 0;
    while i < len {
        if bytes[i] != b'[' {
            i += 1;
            continue;
        }
        if let Some(tok) = try_parse_at(bytes, i) {
            i = tok.end;
            out.push(tok);
        } else {
            i += 1;
        }
    }
    out
}

/// Attempt to parse a token starting at `open` (which must be `[`).
fn try_parse_at(bytes: &[u8], open: usize) -> Option<ParsedToken> {
    let (label, discriminator, end) = token_parts(bytes, open)?;
    Some(ParsedToken {
        start: open,
        end,
        // Safe: both ranges are ASCII by construction.
        label: String::from_utf8_lossy(&bytes[label]).into_owned(),
        discriminator: String::from_utf8_lossy(&bytes[discriminator]).into_owned(),
    })
}

/// Allocation-free token positions for restoration preflight and rendering.
/// The iterator stops scanning as soon as its caller rejects a resource budget.
pub(crate) fn token_ranges(text: &str) -> impl Iterator<Item = std::ops::Range<usize>> + '_ {
    let bytes = text.as_bytes();
    let mut cursor = 0;
    std::iter::from_fn(move || {
        while cursor < bytes.len() {
            let start = cursor;
            cursor += 1;
            if bytes[start] == b'[' {
                if let Some((_, _, end)) = token_parts(bytes, start) {
                    cursor = end;
                    return Some(start..end);
                }
            }
        }
        None
    })
}

fn token_parts(
    bytes: &[u8],
    open: usize,
) -> Option<(std::ops::Range<usize>, std::ops::Range<usize>, usize)> {
    let len = bytes.len();
    let mut i = open + 1;

    // label = [A-Z][A-Za-z]{0,31} — must start uppercase (ADR-0003 §1).
    let label_start = i;
    if i >= len || !bytes[i].is_ascii_uppercase() {
        return None;
    }
    i += 1;
    while i < len && bytes[i].is_ascii_alphabetic() {
        i += 1;
    }
    let label_end = i;
    if label_end - label_start > 32 {
        return None;
    }

    // separator
    if i >= len || bytes[i] != b'_' {
        return None;
    }
    i += 1;

    // discriminator = [0-9a-f]+, at least DISCRIMINATOR_LEN
    let disc_start = i;
    while i < len && is_lower_hex(bytes[i]) {
        i += 1;
    }
    if i - disc_start < DISCRIMINATOR_LEN {
        return None;
    }
    let disc_end = i;

    // close
    if i >= len || bytes[i] != b']' {
        return None;
    }
    let end = i + 1;

    Some((label_start..label_end, disc_start..disc_end, end))
}

fn is_lower_hex(b: u8) -> bool {
    b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
}

fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn label_for_known_types() {
        assert_eq!(label_for("EMAIL_ADDRESS"), "Email");
        assert_eq!(label_for("US_SSN"), "Ssn");
        assert_eq!(label_for("SSN"), "Ssn");
        assert_eq!(label_for("PERSON"), "Person");
        assert_eq!(label_for("EXECUTIVE_NAME"), "Person"); // many-to-one
        assert_eq!(label_for("CREDIT_CARD"), "CreditCard");
    }

    #[test]
    fn label_for_unknown_falls_back_to_camelcase() {
        assert_eq!(label_for("COUNSEL_COMMUNICATION"), "CounselCommunication");
        assert_eq!(label_for("MNPI_MARKER"), "MnpiMarker");
        assert_eq!(label_for("DEAL_VALUE"), "DealValue");
    }

    #[test]
    fn labels_never_contain_underscore() {
        for (label, _) in LABEL_TABLE {
            assert!(!label.contains('_'), "label {label} must not contain '_'");
        }
        // Fallback also strips underscores.
        assert!(!label_for("A_B_C_MARKER").contains('_'));
    }

    #[test]
    fn canonicalize_normalizes_ws_and_case() {
        assert_eq!(canonicalize("  Alice   Smith "), "alice smith");
        assert_eq!(canonicalize("ALICE@EXAMPLE.COM"), "alice@example.com");
        assert_eq!(canonicalize("a\t\nb"), "a b");
    }

    #[test]
    fn discriminator_is_8_lower_hex() {
        let salt = [7u8; SALT_LEN];
        let d = discriminator(&salt, "Email", "alice@example.com");
        assert_eq!(d.len(), DISCRIMINATOR_LEN);
        assert!(
            d.bytes().all(is_lower_hex),
            "disc must be lowercase hex: {d}"
        );
    }

    #[test]
    fn discriminator_is_stable_within_same_salt() {
        let salt = [42u8; SALT_LEN];
        let a = discriminator(&salt, "Email", "alice@example.com");
        let b = discriminator(&salt, "Email", "alice@example.com");
        assert_eq!(a, b, "same (salt,label,value) must give same discriminator");
    }

    #[test]
    fn discriminator_differs_across_salts() {
        let a = discriminator(&[1u8; SALT_LEN], "Email", "alice@example.com");
        let b = discriminator(&[2u8; SALT_LEN], "Email", "alice@example.com");
        assert_ne!(
            a, b,
            "different salt must (overwhelmingly) give different token"
        );
    }

    #[test]
    fn discriminator_includes_label() {
        // Same value, different label → different discriminator (label is in the MAC).
        let salt = [9u8; SALT_LEN];
        let a = discriminator(&salt, "Email", "x");
        let b = discriminator(&salt, "Person", "x");
        assert_ne!(a, b);
    }

    #[test]
    fn full_discriminator_extends_default() {
        let salt = [3u8; SALT_LEN];
        let full = full_discriminator(&salt, "Email", "a@b.com");
        let short = discriminator(&salt, "Email", "a@b.com");
        assert_eq!(full.len(), 64);
        assert!(full.starts_with(&short));
        assert!(full[..DISCRIMINATOR_LEN_EXTENDED].starts_with(&short));
    }

    #[test]
    fn emit_and_parse_round_trip() {
        let t = emit("Email", "3f8a2c1b");
        assert_eq!(t, "[Email_3f8a2c1b]");
        let parsed = parse_tokens(&format!("x {t} y"));
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].label, "Email");
        assert_eq!(parsed[0].discriminator, "3f8a2c1b");
        assert_eq!(parsed[0].as_token(), t);
    }

    #[test]
    fn parse_finds_multiple_tokens_with_offsets() {
        let text = "[Email_aaaaaaaa] to [Ssn_bbbbbbbb]!";
        let toks = parse_tokens(text);
        assert_eq!(toks.len(), 2);
        assert_eq!(&text[toks[0].start..toks[0].end], "[Email_aaaaaaaa]");
        assert_eq!(&text[toks[1].start..toks[1].end], "[Ssn_bbbbbbbb]");
    }

    #[test]
    fn allocation_free_ranges_match_public_parser() {
        let text = "前 [[Email_aaaaaaaa]] [email_aaaaaaaa] [Ssn_0123456789abcdef] fin";
        let ranges: Vec<_> = token_ranges(text).collect();
        let parsed = parse_tokens(text);
        assert_eq!(
            ranges,
            parsed
                .iter()
                .map(|token| token.start..token.end)
                .collect::<Vec<_>>()
        );
        assert_eq!(
            ranges
                .iter()
                .map(|range| &text[range.clone()])
                .collect::<Vec<_>>(),
            vec!["[Email_aaaaaaaa]", "[Ssn_0123456789abcdef]"]
        );
        // A large discriminator is represented only by offsets, without copying it.
        let long = format!("[Email_{}]", "a".repeat(1_000_000));
        assert_eq!(token_ranges(&long).next(), Some(0..long.len()));
    }

    #[test]
    fn parse_ignores_non_tokens() {
        // Uppercase hex, spaces, short hex, prose brackets — none match.
        for s in [
            "[Email_ABCDEF12]", // uppercase disc
            "[Email_short1]",   // <8 hex
            "[email_aaaaaaaa]", // lowercase label start
            "[Email aaaaaaaa]", // space, no underscore
            "[Email_gggggggg]", // g is not hex
            "plain [bracketed] text",
            "[[Email_aaaaaaaa]]", // double bracket is fine — inner still parses
        ] {
            // Only the last one contains a valid inner token.
            let n = parse_tokens(s).len();
            if s == "[[Email_aaaaaaaa]]" {
                assert_eq!(n, 1, "inner token should parse in {s:?}");
            } else {
                assert_eq!(n, 0, "must not parse a token in {s:?}");
            }
        }
    }

    #[test]
    fn parse_accepts_extended_discriminator() {
        let toks = parse_tokens("[Person_0123456789ab]");
        assert_eq!(toks.len(), 1);
        assert_eq!(toks[0].discriminator, "0123456789ab");
        assert_eq!(toks[0].discriminator.len(), DISCRIMINATOR_LEN_EXTENDED);
    }

    #[test]
    fn opaque_label_is_grammar_safe() {
        assert!(!OPAQUE_LABEL.contains('_'));
        assert!(OPAQUE_LABEL.chars().all(|c| c.is_ascii_alphabetic()));
    }

    #[test]
    fn label_table_matches_shared_fixture() {
        // The Rust table is the runtime source; the JSON fixture is the shared,
        // cross-repo source. They must agree, or Redact and Shield drift.
        let json = include_str!("../tests/fixtures/category-labels.json");
        let parsed: serde_json::Value = serde_json::from_str(json).expect("fixture is valid JSON");
        let map = parsed["label_to_entity_types"]
            .as_object()
            .expect("label_to_entity_types object");

        assert_eq!(
            map.len(),
            LABEL_TABLE.len(),
            "fixture and Rust table have different label counts"
        );
        for (label, types) in LABEL_TABLE {
            let fixture_types: Vec<String> = map[*label]
                .as_array()
                .unwrap_or_else(|| panic!("fixture missing label {label}"))
                .iter()
                .map(|v| v.as_str().unwrap().to_owned())
                .collect();
            let rust_types: Vec<String> = types.iter().map(|s| (*s).to_owned()).collect();
            assert_eq!(
                &fixture_types, &rust_types,
                "entity types differ for {label}"
            );
        }
    }
    #[test]
    fn custom_labels_always_emit_parseable_bounded_tokens() {
        for category in [
            "TYPE-2",
            "SENSITIVE_DATA_123",
            "ÉMAIL",
            "",
            "123",
            "averylongcategorywithmorethanthirtytwocharacters",
        ] {
            let label = label_for(category);
            let parsed = parse_tokens(&emit(&label, "12345678"));
            assert_eq!(parsed.len(), 1, "category={category:?} label={label:?}");
            assert!(label.len() <= 32);
        }
        assert!(parse_tokens(&format!("[{}_12345678]", "A".repeat(33))).is_empty());
    }
}
