//! Property tests for within-call token collision-freedom (OGE-1209 R3 AC).
//!
//! The [`TokenAssigner`] gives each distinct `(label, canonical_value)` in one
//! call a distinct `[Label_<salted-hex>]` token, extending the discriminator
//! 8 → 12 hex on the (astronomically rare) 32-bit collision. These properties
//! assert the observable guarantee through the public one-way API, across many
//! random value sets and salts:
//!
//! 1. distinct values → distinct tokens (no collision merges two originals), and
//! 2. the whole text round-trips exactly.
//!
//! A genuine collision would violate BOTH at once — the token count would drop
//! below the distinct-value count, and unredact would restore one value as
//! another — so together they pin the invariant.

use std::collections::HashSet;

use ogentic_redact_core::{redact_one_way_with_salt, unredact_one_way};
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(500))]

    #[test]
    fn distinct_values_never_collide_within_a_call(
        // Any-length salt, including empty (HMAC accepts any key length).
        salt in proptest::collection::vec(any::<u8>(), 0..=32),
        // A set of distinct, lowercase email local-parts → distinct emails.
        locals in proptest::collection::hash_set("[a-z][a-z0-9]{0,9}", 1..40),
    ) {
        let emails: Vec<String> =
            locals.iter().map(|l| format!("{l}@example.com")).collect();
        let text = emails.join(" and ");

        let result = redact_one_way_with_salt(&text, &salt);

        // (1a) Every distinct email is detected and gets its own map entry.
        prop_assert_eq!(
            result.tokens.len(),
            emails.len(),
            "distinct emails must map to distinct tokens (no collision)\n  salt={:?}\n  tokens={:?}",
            salt,
            result.tokens
        );

        // (1b) The token→original map is injective: no two tokens share an
        // original, and (by len equality above) no two originals share a token.
        let originals: HashSet<&String> = result.tokens.values().collect();
        prop_assert_eq!(originals.len(), result.tokens.len(), "duplicate originals in map");

        // (1c) Every emitted token key is present in the redacted text, and no
        // raw email survives.
        for (tok, original) in &result.tokens {
            prop_assert!(result.text.contains(tok.as_str()), "token {tok} missing from text");
            prop_assert!(!result.text.contains(original.as_str()), "PII {original} leaked");
        }

        // (2) Round-trip restores the exact input.
        prop_assert_eq!(unredact_one_way(&result.text, &result.tokens), text);
    }

    #[test]
    fn repeated_value_collapses_to_one_token(
        salt in proptest::collection::vec(any::<u8>(), 0..=32),
        local in "[a-z][a-z0-9]{0,9}",
        repeats in 2usize..8,
    ) {
        // The same email repeated N times must yield exactly one token (stable
        // within a call) and still round-trip.
        let email = format!("{local}@example.com");
        let text = vec![email.as_str(); repeats].join(", ");

        let result = redact_one_way_with_salt(&text, &salt);

        prop_assert_eq!(result.tokens.len(), 1, "same value must reuse one token");
        prop_assert_eq!(unredact_one_way(&result.text, &result.tokens), text);
    }
}
