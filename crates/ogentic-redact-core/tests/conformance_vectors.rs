//! F3 cross-language conformance test — Rust surface.
//!
//! Loads `conformance/vectors.json` from the repo root and verifies that
//! `ogentic_redact_core::redact_one_way` produces byte-identical output to
//! what the vector file specifies.  Any divergence is a CI failure.
//!
//! Run: `cargo test -p ogentic-redact-core --test conformance_vectors`

use std::collections::HashMap;
use std::path::PathBuf;

use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct VectorFile {
    vectors: Vec<Vector>,
}

#[derive(Debug, Deserialize)]
struct Vector {
    id: String,
    input: String,
    expected_text: String,
    expected_tokens: HashMap<String, String>,
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
    let file: VectorFile = serde_json::from_str(&json)
        .unwrap_or_else(|e| panic!("cannot parse vectors.json: {e}"));

    assert!(!file.vectors.is_empty(), "vectors.json must contain at least one vector");

    for v in &file.vectors {
        let result = ogentic_redact_core::redact_one_way(&v.input);

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
    }
}
