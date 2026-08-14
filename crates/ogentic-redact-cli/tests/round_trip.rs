//! Acceptance tests for the `ogentic-redact` CLI (OGE-1266).
//!
//! Drives the built binary end-to-end through temp files, covering each AC:
//! redacted stdout + vault file, restore-from-vault, vault-never-inlined, an
//! exact round-trip, and the `--cloud` first-use warning.

use std::fs;
use std::path::PathBuf;
use std::process::Command;

/// Path to the freshly built CLI binary (Cargo sets this for integration tests).
const BIN: &str = env!("CARGO_BIN_EXE_ogentic-redact");

const SAMPLE: &str = "Contact Alice at alice@example.com or call 415-555-0132. SSN 123-45-6789.";

/// A unique scratch directory for one test, cleaned up on drop.
struct Scratch {
    dir: PathBuf,
}

impl Scratch {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("ogr-cli-{}-{}", tag, std::process::id()));
        fs::create_dir_all(&dir).expect("create scratch dir");
        Self { dir }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

/// Run the CLI with `args`, returning `(stdout, stderr)`. Asserts success.
fn run(args: &[&str]) -> (String, String) {
    let output = Command::new(BIN).args(args).output().expect("spawn CLI");
    assert!(
        output.status.success(),
        "CLI exited non-zero: {:?}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr),
    );
    (
        String::from_utf8(output.stdout).expect("stdout is utf-8"),
        String::from_utf8(output.stderr).expect("stderr is utf-8"),
    )
}

#[test]
fn redact_writes_stdout_and_vault_then_unredact_round_trips() {
    let scratch = Scratch::new("roundtrip");
    let input = scratch.path("input.txt");
    let vault = scratch.path("vault.json");
    let redacted_file = scratch.path("redacted.txt");
    fs::write(&input, SAMPLE).unwrap();

    // AC1: forward redaction → redacted stdout + vault file.
    let (redacted, _) = run(&[
        input.to_str().unwrap(),
        "--mapping",
        vault.to_str().unwrap(),
    ]);
    assert!(vault.exists(), "vault file was not written");

    // Sensitive values are gone from the redacted output...
    for secret in ["alice@example.com", "415-555-0132", "123-45-6789"] {
        assert!(
            !redacted.contains(secret),
            "redacted output still contains {secret:?}: {redacted:?}"
        );
    }
    // ...and replaced by the ADR-0003 `[Label_<hex>]` grammar.
    assert!(redacted.contains("[Email_"), "no Email token: {redacted:?}");

    // AC3: the vault is a separate file and is never inlined into stdout.
    let vault_body = fs::read_to_string(&vault).unwrap();
    assert!(
        !redacted.contains(&vault_body) && !redacted.contains("\"tokens\""),
        "vault appears to be inlined into redacted output"
    );
    // The vault does hold the originals (that is its purpose).
    assert!(vault_body.contains("alice@example.com"));

    // AC2 + AC4: unredact from the vault reproduces the input exactly.
    fs::write(&redacted_file, &redacted).unwrap();
    let (restored, _) = run(&[
        "unredact",
        redacted_file.to_str().unwrap(),
        "--mapping",
        vault.to_str().unwrap(),
    ]);
    assert_eq!(restored, SAMPLE, "round-trip did not reproduce the input");
}

#[test]
fn without_mapping_flag_no_vault_is_written() {
    let scratch = Scratch::new("oneway");
    let input = scratch.path("input.txt");
    fs::write(&input, SAMPLE).unwrap();

    let (redacted, _) = run(&[input.to_str().unwrap()]);
    assert!(!redacted.contains("alice@example.com"));
    // No vault path given → one-way, and nothing else is created in the dir.
    let entries: Vec<_> = fs::read_dir(&scratch.dir)
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert_eq!(entries, vec![std::ffi::OsString::from("input.txt")]);
}

#[test]
fn clean_input_round_trips_and_writes_empty_vault() {
    let scratch = Scratch::new("clean");
    let input = scratch.path("input.txt");
    let vault = scratch.path("vault.json");
    let redacted_file = scratch.path("redacted.txt");
    let clean = "Nothing sensitive here.";
    fs::write(&input, clean).unwrap();

    let (redacted, _) = run(&[
        input.to_str().unwrap(),
        "--mapping",
        vault.to_str().unwrap(),
    ]);
    assert_eq!(redacted, clean);

    fs::write(&redacted_file, &redacted).unwrap();
    let (restored, _) = run(&[
        "unredact",
        redacted_file.to_str().unwrap(),
        "--mapping",
        vault.to_str().unwrap(),
    ]);
    assert_eq!(restored, clean);
}

#[test]
fn cloud_flag_emits_first_use_warning() {
    let scratch = Scratch::new("cloud");
    let input = scratch.path("input.txt");
    fs::write(&input, SAMPLE).unwrap();

    // AC5: cloud is opt-in and warns on first use.
    let (_, stderr) = run(&["--cloud", input.to_str().unwrap()]);
    assert!(
        stderr.contains("cloud-assisted recognisers are enabled"),
        "expected a cloud opt-in warning, got: {stderr:?}"
    );

    // Default path is silent (on-device only).
    let (_, stderr_default) = run(&[input.to_str().unwrap()]);
    assert!(
        stderr_default.is_empty(),
        "default path should not warn, got: {stderr_default:?}"
    );
}
