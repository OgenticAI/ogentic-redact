//! Regenerate `conformance/vectors.json` for the ADR-0003 grammar.
//!
//! Reads the existing vector ids / descriptions / inputs, recomputes
//! `expected_text` and `expected_tokens` under a FIXED salt (so the salted-hex
//! tokens are reproducible and cross-language byte-identity is testable), and
//! self-checks each with a round-trip. Rust is the golden generator; the
//! Python / Node / Swift conformance runners must reproduce these exact bytes.
//!
//! Run: `cargo run -p ogentic-redact-core --example gen_vectors`

use std::collections::BTreeMap;
use std::path::PathBuf;

use ogentic_redact_core::{redact_one_way_with_salt, unredact_one_way};
use serde_json::{json, Map, Value};

/// The fixed conformance salt: bytes 0x00..0x0f. Must match `TEST_SALT` in the
/// core tests and `call_salt_hex` written below.
const SALT: [u8; 16] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
];
const SALT_HEX: &str = "000102030405060708090a0b0c0d0e0f";

fn vectors_path() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("../../conformance/vectors.json");
    p
}

fn main() {
    let path = vectors_path();
    let existing: Value =
        serde_json::from_str(&std::fs::read_to_string(&path).expect("read vectors.json"))
            .expect("parse vectors.json");

    let mut out_vectors = Vec::new();
    for v in existing["vectors"].as_array().expect("vectors array") {
        let id = v["id"].as_str().unwrap();
        let description = v["description"].as_str().unwrap_or("");
        let input = v["input"].as_str().unwrap();

        let result = redact_one_way_with_salt(input, &SALT);

        // Self-check: the golden file must round-trip.
        let restored = unredact_one_way(&result.text, &result.tokens);
        assert_eq!(restored, input, "[{id}] round-trip failed while generating");

        // Deterministic key order for a stable file.
        let tokens: BTreeMap<&String, &String> = result.tokens.iter().collect();
        let mut tok_obj = Map::new();
        for (k, val) in tokens {
            tok_obj.insert(k.clone(), Value::String(val.clone()));
        }

        out_vectors.push(json!({
            "id": id,
            "description": description,
            "input": input,
            "expected_text": result.text,
            "expected_tokens": Value::Object(tok_obj),
        }));
    }

    let doc = json!({
        "version": "f4",
        "description": "F4 golden vectors — cross-language conformance for the ADR-0003 \
                        token grammar `[Label_<salted-hex>]`. Every surface (Rust, Python, \
                        Node.js, Swift), given `input` and the fixed `call_salt_hex`, must \
                        produce byte-identical `expected_text` and `expected_tokens`, and \
                        must round-trip (unredact restores `input`).",
        "call_salt_hex": SALT_HEX,
        "vectors": out_vectors,
    });

    let mut s = serde_json::to_string_pretty(&doc).expect("serialize");
    s.push('\n');
    std::fs::write(&path, s).expect("write vectors.json");
    eprintln!(
        "wrote {} vectors to {}",
        doc["vectors"].as_array().unwrap().len(),
        path.display()
    );
}
