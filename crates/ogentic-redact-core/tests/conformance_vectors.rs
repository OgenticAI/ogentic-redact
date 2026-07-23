//! F4 cross-language conformance test — Rust surface (ADR-0003 grammar).
//!
//! Loads `conformance/vectors.json`, redacts each `input` under the file's
//! fixed `call_salt_hex`, and verifies that `redact_one_way_with_salt` produces
//! byte-identical `expected_text` / `expected_tokens` AND that `unredact_one_way`
//! restores the original. Any divergence is a CI failure. The Python / Node /
//! Swift runners assert the same file, so all four surfaces must agree.
//!
//! Run: `cargo test -p ogentic-redact-core --test conformance_vectors`

use std::collections::HashMap;
use std::path::PathBuf;

use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct VectorFile {
    call_salt_hex: String,
    vectors: Vec<Vector>,
}

#[derive(Debug, Deserialize)]
struct Vector {
    id: String,
    input: String,
    expected_text: String,
    expected_tokens: HashMap<String, String>,
}

fn decode_hex(s: &str) -> Vec<u8> {
    assert!(s.len() % 2 == 0, "call_salt_hex must have even length");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex in call_salt_hex"))
        .collect()
}

fn vectors_path() -> PathBuf {
    // CARGO_MANIFEST_DIR = <repo>/crates/ogentic-redact-core
    // vectors.json       = <repo>/conformance/vectors.json  (2 levels up)
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("../../conformance/vectors.json");
    p
}

#[test]
fn f3_vectors_rust_surface() {
    let path = vectors_path();
    let json = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    let file: VectorFile =
        serde_json::from_str(&json).unwrap_or_else(|e| panic!("cannot parse vectors.json: {e}"));

    assert!(
        !file.vectors.is_empty(),
        "vectors.json must contain at least one vector"
    );

    let salt = decode_hex(&file.call_salt_hex);

    for v in &file.vectors {
        let result = ogentic_redact_core::redact_one_way_with_salt(&v.input, &salt);

        assert_eq!(
            result.text, v.expected_text,
            "[{}] `text` mismatch\n  input:    {:?}\n  got:      {:?}\n  expected: {:?}",
            v.id, v.input, result.text, v.expected_text
        );
        assert_eq!(
            result.tokens, v.expected_tokens,
            "[{}] `tokens` mismatch\n  input:    {:?}\n  got:      {:?}\n  expected: {:?}",
            v.id, v.input, result.tokens, v.expected_tokens
        );

        // Round-trip: unredact must restore the exact input (ADR-0003 §9).
        let restored = ogentic_redact_core::unredact_one_way(&result.text, &result.tokens);
        assert_eq!(
            restored, v.input,
            "[{}] round-trip mismatch\n  got:      {:?}\n  expected: {:?}",
            v.id, restored, v.input
        );
    }
}
