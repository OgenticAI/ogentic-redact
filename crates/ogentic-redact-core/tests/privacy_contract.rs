//! Public privacy and lossless-restoration contract regressions.
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Barrier};

use ogentic_redact_core::{
    redact, redact_one_way_with_salt, redact_spans, redact_spans_with_salt,
    redact_to_mapping_with_salt, redact_with_salt, token, unredact, unredact_and_delete,
    unredact_and_delete_with_limits, unredact_one_way, unredact_one_way_with_limits, MappingStore,
    RedactError, RedactMode, RestorationLimits, Span,
};

const SALT: [u8; 16] = [0; 16];

#[test]
fn default_result_cannot_serialize_originals_or_mapping() {
    let input = "Alice@example.com Alice@example.com; call 415-555-0132. SSN 123-45-6789.";
    let result = redact_one_way_with_salt(input, &SALT);
    let json = serde_json::to_value(&result).unwrap();
    assert_eq!(json.as_object().unwrap().len(), 2);
    assert!(json.get("tokens").is_none());
    assert_eq!(result.redaction_count, 4);
    assert!(!result.is_clean());
    for secret in ["Alice@example.com", "415-555-0132", "123-45-6789"] {
        assert!(!json.to_string().contains(secret));
    }
}

#[test]
fn scanner_modes_protect_all_supported_entities_and_restore_exact_case() {
    let input = "Alice@example.com alice@example.com. Call (415) 555-0100 or +1-800-555-0199. SSN 123-45-6789.";
    let mapping = redact_to_mapping_with_salt(input, &SALT);
    assert_eq!(mapping.tokens.len(), 5);
    for secret in [
        "Alice@example.com",
        "alice@example.com",
        "(415) 555-0100",
        "+1-800-555-0199",
        "123-45-6789",
    ] {
        assert!(!mapping.text.contains(secret));
    }
    assert_eq!(
        unredact_one_way(&mapping.text, &mapping.tokens).unwrap(),
        input
    );
    let store = MappingStore::new();
    let (text, id) = redact_with_salt(
        input,
        "default",
        RedactMode::Reversible,
        Some(&store),
        &SALT,
    )
    .unwrap();
    assert_eq!(
        text, mapping.text,
        "store scanner must match one-way scanner coverage"
    );
    assert_eq!(unredact(&text, &id.unwrap(), &store).unwrap(), input);
    assert_eq!(redact_one_way_with_salt(input, &SALT).text, text);
}

#[test]
fn source_literal_matching_generated_token_is_reserved() {
    let first = redact_to_mapping_with_salt("alice@example.com", &SALT);
    let literal = first.tokens.keys().next().unwrap();
    let input = format!("alice@example.com example:{literal} alice@example.com");
    let result = redact_to_mapping_with_salt(&input, &SALT);
    assert!(
        result.text.contains(literal),
        "literal source content must stay intact"
    );
    assert!(!result.tokens.contains_key(literal));
    assert_eq!(
        result.tokens.len(),
        1,
        "repeated exact value still shares a token"
    );
    assert_eq!(
        unredact_one_way(&result.text, &result.tokens).unwrap(),
        input
    );
}

#[test]
fn known_32_bit_collision_extends_and_restores_both_values() {
    let input = "x94428@example.com x97004@example.com";
    let result = redact_to_mapping_with_salt(input, &SALT);
    assert_eq!(result.text, "[Email_788948cf] [Email_788948cfb5fd]");
    assert_eq!(
        unredact_one_way(&result.text, &result.tokens).unwrap(),
        input
    );
}

#[test]
fn supplied_unicode_spans_and_whitespace_variants_restore_exactly() {
    let input = "José / Alice  Smith / Alice Smith";
    let values = ["José", "Alice  Smith", "Alice Smith"];
    let mut spans: Vec<_> = values
        .iter()
        .map(|value| {
            let start = input.find(value).unwrap();
            Span {
                start,
                end: start + value.len(),
                entity_type: "PERSON".to_owned(),
            }
        })
        .collect();
    spans.reverse(); // Input order is not required to be sorted.
    let store = MappingStore::new();
    let (text, id) = redact_spans(input, &spans, RedactMode::Reversible, Some(&store)).unwrap();
    let tokens = token::parse_tokens(&text);
    assert_eq!(tokens.len(), 3);
    assert_eq!(
        tokens
            .iter()
            .map(|t| t.as_token())
            .collect::<HashSet<_>>()
            .len(),
        3
    );
    for value in values {
        assert!(!text.contains(value));
    }
    assert_eq!(unredact(&text, &id.unwrap(), &store).unwrap(), input);
}

#[test]
fn invalid_or_overlapping_spans_fail_without_storing_anything() {
    let store = MappingStore::new();
    for (start, end) in [
        (1, 2),
        (0, 1),
        (2, 2),
        (2, 1),
        (0, 100),
        (usize::MAX, usize::MAX),
    ] {
        let span = Span {
            start,
            end,
            entity_type: "PERSON".to_owned(),
        };
        assert!(matches!(
            redact_spans("éX", &[span], RedactMode::Reversible, Some(&store)),
            Err(RedactError::InvalidSpan { .. })
        ));
    }
    let spans = [
        Span {
            start: 0,
            end: 3,
            entity_type: "PERSON".to_owned(),
        },
        Span {
            start: 2,
            end: 3,
            entity_type: "PERSON".to_owned(),
        },
    ];
    assert!(matches!(
        redact_spans("éX", &spans, RedactMode::Reversible, Some(&store)),
        Err(RedactError::OverlappingSpans)
    ));
    let empty_type = Span {
        start: 0,
        end: 2,
        entity_type: "  ".to_owned(),
    };
    assert!(matches!(
        redact_spans("éX", &[empty_type], RedactMode::Reversible, Some(&store)),
        Err(RedactError::InvalidEntityType { .. })
    ));
    assert!(store.is_empty());
}

#[test]
fn custom_category_and_token_shaped_original_round_trip_without_cascade() {
    let input = "Alice / [Person_12345678] / secret";
    let mut spans = Vec::new();
    for (value, category) in [
        ("Alice", "TYPE-2"),
        ("[Person_12345678]", "SENSITIVE_DATA_123"),
        ("secret", "ÉMAIL"),
    ] {
        let start = input.find(value).unwrap();
        spans.push(Span {
            start,
            end: start + value.len(),
            entity_type: category.to_owned(),
        });
    }
    let store = MappingStore::new();
    let (text, id) =
        redact_spans_with_salt(input, &spans, RedactMode::Reversible, Some(&store), &SALT).unwrap();
    assert_eq!(token::parse_tokens(&text).len(), 3);
    assert_eq!(
        unredact_and_delete(&text, &id.unwrap(), &store).unwrap(),
        input
    );
    assert!(store.is_empty());
}

#[test]
fn stores_have_secret_free_debug_and_explicit_deletion() {
    let store = MappingStore::new();
    let (text, id) = redact(
        "secret@example.com",
        "default",
        RedactMode::Reversible,
        Some(&store),
    )
    .unwrap();
    let id = id.unwrap();
    assert_eq!(store.len(), 1);
    let diagnostic = format!("{store:?}");
    assert!(!diagnostic.contains("secret"));
    assert!(!diagnostic.contains(&id));
    assert!(!diagnostic.contains("call_salt"));
    assert!(store.delete(&id));
    assert!(!store.delete(&id));
    assert!(matches!(
        unredact(&text, &id, &store),
        Err(RedactError::UnknownMappingId { .. })
    ));
    let explicit = redact_to_mapping_with_salt("secret@example.com", &SALT);
    assert!(!format!("{explicit:?}").contains("secret"));
}

#[test]
fn consuming_restoration_has_exactly_one_concurrent_winner() {
    let store = Arc::new(MappingStore::new());
    let (text, id) = redact(
        "alice@example.com",
        "default",
        RedactMode::Reversible,
        Some(&store),
    )
    .unwrap();
    let id = id.unwrap();
    let barrier = Arc::new(Barrier::new(2));
    let handles: Vec<_> = (0..2)
        .map(|_| {
            let (store, text, id, barrier) = (
                Arc::clone(&store),
                text.clone(),
                id.clone(),
                Arc::clone(&barrier),
            );
            std::thread::spawn(move || {
                barrier.wait();
                unredact_and_delete(&text, &id, &store)
            })
        })
        .collect();
    let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(results.iter().filter(|result| result.is_err()).count(), 1);
    assert!(store.is_empty());
}

#[test]
fn restoration_limits_count_utf8_bytes_and_mapped_occurrences() {
    let tokens = HashMap::from([("[Person_12345678]".to_owned(), "é".to_owned())]);
    let limits = RestorationLimits {
        max_output_bytes: 2,
        max_replacements: 1,
    };
    assert_eq!(
        unredact_one_way_with_limits("[Person_12345678]", &tokens, limits).unwrap(),
        "é"
    );
    for limits in [
        RestorationLimits {
            max_output_bytes: 1,
            ..limits
        },
        RestorationLimits {
            max_replacements: 0,
            ..limits
        },
    ] {
        assert!(matches!(
            unredact_one_way_with_limits("[Person_12345678]", &tokens, limits),
            Err(RedactError::RestorationLimitExceeded)
        ));
    }
    assert!(matches!(
        unredact_one_way_with_limits(
            "[Person_12345678][Person_12345678]",
            &tokens,
            RestorationLimits {
                max_output_bytes: 4,
                max_replacements: 1
            }
        ),
        Err(RedactError::RestorationLimitExceeded)
    ));
    let limits = RestorationLimits {
        max_output_bytes: 0,
        max_replacements: 0,
    };
    assert_eq!(
        unredact_one_way_with_limits("", &tokens, limits).unwrap(),
        ""
    );
    assert!(unredact_one_way_with_limits("x", &tokens, limits).is_err());
    let unknown = "[Person_87654321]";
    assert_eq!(
        unredact_one_way_with_limits(
            unknown,
            &tokens,
            RestorationLimits {
                max_output_bytes: unknown.len(),
                max_replacements: 0
            }
        )
        .unwrap(),
        unknown
    );
}

#[test]
fn default_restoration_rejects_amplification_and_excess_replacements() {
    let token = "[Person_12345678]";
    let tokens = HashMap::from([(token.to_owned(), "x".repeat(64 * 1024))]);
    assert!(matches!(
        unredact_one_way(&token.repeat(1024), &tokens),
        Err(RedactError::RestorationLimitExceeded)
    ));
    let empty = HashMap::from([(token.to_owned(), String::new())]);
    assert!(matches!(
        unredact_one_way(&token.repeat(100_001), &empty),
        Err(RedactError::RestorationLimitExceeded)
    ));
}

#[test]
fn rejected_consumption_preserves_mapping_for_a_valid_retry() {
    let store = MappingStore::new();
    let (text, id) = redact(
        "alice@example.com",
        "default",
        RedactMode::Reversible,
        Some(&store),
    )
    .unwrap();
    let id = id.unwrap();
    assert!(matches!(
        unredact_and_delete_with_limits(
            &text,
            &id,
            &store,
            RestorationLimits {
                max_output_bytes: 1,
                max_replacements: 1
            }
        ),
        Err(RedactError::RestorationLimitExceeded)
    ));
    assert_eq!(store.len(), 1);
    assert_eq!(
        unredact_and_delete(&text, &id, &store).unwrap(),
        "alice@example.com"
    );
    assert!(store.is_empty());
}
