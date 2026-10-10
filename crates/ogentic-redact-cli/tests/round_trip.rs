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

#[test]
fn unknown_mapping_version_fails_before_writing_output() {
    let scratch = Scratch::new("bad-version");
    let input = scratch.path("redacted.txt");
    let mapping = scratch.path("mapping.json");
    fs::write(&input, "[Email_12345678]").unwrap();
    fs::write(
        &mapping,
        r#"{"version":"future-format","tokens":{"[Email_12345678]":"secret@example.com"}}"#,
    )
    .unwrap();
    let output = Command::new(BIN)
        .args([
            "unredact",
            input.to_str().unwrap(),
            "--mapping",
            mapping.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let error = String::from_utf8_lossy(&output.stderr);
    assert!(error.contains("unsupported mapping format version"));
    assert!(!error.contains("secret@example.com"));
}

#[test]
fn mixed_case_and_unicode_surroundings_restore_without_changes() {
    let scratch = Scratch::new("exact-variants");
    let input = scratch.path("input.txt");
    let mapping = scratch.path("mapping.json");
    let redacted_path = scratch.path("redacted.txt");
    let original = "José: Alice@example.com alice@example.com.\n";
    fs::write(&input, original).unwrap();
    let (redacted, _) = run(&[
        input.to_str().unwrap(),
        "--mapping",
        mapping.to_str().unwrap(),
    ]);
    assert!(!redacted.contains("example.com"));
    fs::write(&redacted_path, redacted).unwrap();
    let (restored, _) = run(&[
        "unredact",
        redacted_path.to_str().unwrap(),
        "--mapping",
        mapping.to_str().unwrap(),
    ]);
    assert_eq!(restored, original);
}

#[test]
fn vault_refuses_existing_files_and_input_aliases_without_stdout() {
    let scratch = Scratch::new("no-clobber");
    let input = scratch.path("input.txt");
    let vault = scratch.path("vault.json");
    fs::write(&input, SAMPLE).unwrap();
    fs::write(&vault, "existing vault content").unwrap();
    for destination in [&input, &vault] {
        let output = Command::new(BIN)
            .args([
                input.to_str().unwrap(),
                "--mapping",
                destination.to_str().unwrap(),
            ])
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert!(!String::from_utf8_lossy(&output.stderr).contains("alice@example.com"));
    }
    assert_eq!(fs::read_to_string(&input).unwrap(), SAMPLE);
    assert_eq!(
        fs::read_to_string(&vault).unwrap(),
        "existing vault content"
    );
    assert_eq!(
        fs::read_dir(&scratch.dir).unwrap().count(),
        2,
        "temporary vault leaked"
    );
}

#[cfg(unix)]
#[test]
fn vault_refuses_symbolic_hard_and_dangling_links() {
    use std::os::unix::fs::symlink;
    let scratch = Scratch::new("links");
    let input = scratch.path("input.txt");
    fs::write(&input, SAMPLE).unwrap();
    let symbolic = scratch.path("symlink.json");
    let hard = scratch.path("hardlink.json");
    let dangling = scratch.path("dangling.json");
    let absent = scratch.path("absent.json");
    symlink(&input, &symbolic).unwrap();
    fs::hard_link(&input, &hard).unwrap();
    symlink(&absent, &dangling).unwrap();
    for destination in [&symbolic, &hard, &dangling] {
        let output = Command::new(BIN)
            .args([
                input.to_str().unwrap(),
                "--mapping",
                destination.to_str().unwrap(),
            ])
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
    }
    assert_eq!(fs::read_to_string(&input).unwrap(), SAMPLE);
    assert!(fs::symlink_metadata(&dangling)
        .unwrap()
        .file_type()
        .is_symlink());
    assert!(!absent.exists());
    assert_eq!(fs::read_dir(&scratch.dir).unwrap().count(), 4);
}

#[cfg(unix)]
#[test]
fn published_vault_is_owner_only_complete_and_has_no_temporary_sibling() {
    use std::os::unix::fs::PermissionsExt;
    let scratch = Scratch::new("private-mode");
    let input = scratch.path("input.txt");
    let vault = scratch.path("vault.json");
    fs::write(&input, SAMPLE).unwrap();
    run(&[
        input.to_str().unwrap(),
        "--mapping",
        vault.to_str().unwrap(),
    ]);
    assert_eq!(
        fs::metadata(&vault).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let payload: serde_json::Value = serde_json::from_slice(&fs::read(&vault).unwrap()).unwrap();
    assert_eq!(payload["version"], "f4");
    assert_eq!(payload["tokens"].as_object().unwrap().len(), 3);
    assert_eq!(fs::read_dir(&scratch.dir).unwrap().count(), 2);
}

#[test]
fn failed_vault_publication_never_emits_redacted_stdout() {
    let scratch = Scratch::new("failed-publish");
    let input = scratch.path("input.txt");
    let vault = scratch.path("missing/vault.json");
    fs::write(&input, SAMPLE).unwrap();
    let output = Command::new(BIN)
        .args([
            input.to_str().unwrap(),
            "--mapping",
            vault.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert_eq!(fs::read_dir(&scratch.dir).unwrap().count(), 1);
}

#[test]
fn restore_limits_fail_before_stdout_and_leave_vault_usable() {
    let scratch = Scratch::new("restore-limits");
    let input = scratch.path("input.txt");
    let vault = scratch.path("vault.json");
    fs::write(&input, "[Person_12345678]").unwrap();
    let json = r#"{"version":"f4","tokens":{"[Person_12345678]":"é"}}"#;
    fs::write(&vault, json).unwrap();
    for (flag, value) in [("--max-output-bytes", "1"), ("--max-replacements", "0")] {
        let output = Command::new(BIN)
            .args([
                "unredact",
                input.to_str().unwrap(),
                "--mapping",
                vault.to_str().unwrap(),
                flag,
                value,
            ])
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert!(String::from_utf8_lossy(&output.stderr).contains("restoration limit exceeded"));
        assert_eq!(fs::read_to_string(&vault).unwrap(), json);
    }
    assert_eq!(
        run(&[
            "unredact",
            input.to_str().unwrap(),
            "--mapping",
            vault.to_str().unwrap(),
            "--max-output-bytes",
            "2",
            "--max-replacements",
            "1"
        ])
        .0,
        "é"
    );
}

#[cfg(windows)]
#[test]
fn published_vault_has_only_a_protected_owner_rights_grant() {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::{
        Foundation::{LocalFree, GENERIC_ALL},
        Security::{
            Authorization::{ConvertSidToStringSidW, GetNamedSecurityInfoW, SE_FILE_OBJECT},
            GetAce, GetSecurityDescriptorControl, ACCESS_ALLOWED_ACE, DACL_SECURITY_INFORMATION,
            SE_DACL_PROTECTED,
        },
        Storage::FileSystem::FILE_ALL_ACCESS,
    };

    let scratch = Scratch::new("private-dacl");
    let input = scratch.path("input.txt");
    let vault = scratch.path("vault.json");
    fs::write(&input, SAMPLE).unwrap();
    run(&[
        input.to_str().unwrap(),
        "--mapping",
        vault.to_str().unwrap(),
    ]);
    let path: Vec<u16> = vault.as_os_str().encode_wide().chain(Some(0)).collect();
    let mut descriptor = std::ptr::null_mut();
    let mut dacl = std::ptr::null_mut();
    // SAFETY: Win32 owns the returned descriptor; its ACL/ACE pointers are only
    // read while it is live. Both LocalAlloc buffers are released below.
    unsafe {
        assert_eq!(
            GetNamedSecurityInfoW(
                path.as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut dacl,
                std::ptr::null_mut(),
                &mut descriptor
            ),
            0
        );
        assert!(!dacl.is_null(), "a NULL DACL would grant everyone access");
        assert_eq!(
            (*dacl).AceCount,
            1,
            "vault must have no inherited or additional grants"
        );
        let mut control = 0;
        let mut revision = 0;
        assert_ne!(
            GetSecurityDescriptorControl(descriptor, &mut control, &mut revision),
            0
        );
        let mut raw_ace = std::ptr::null_mut();
        assert_ne!(GetAce(dacl, 0, &mut raw_ace), 0);
        let ace = &*raw_ace.cast::<ACCESS_ALLOWED_ACE>();
        assert_eq!(ace.Header.AceType, 0, "expected ACCESS_ALLOWED_ACE_TYPE");
        assert_eq!(
            ace.Header.AceFlags, 0,
            "grant must be explicit and non-inheriting"
        );
        assert!(ace.Mask == FILE_ALL_ACCESS || ace.Mask == GENERIC_ALL);
        let mut sid_string = std::ptr::null_mut();
        assert_ne!(
            ConvertSidToStringSidW(
                std::ptr::addr_of!(ace.SidStart).cast_mut().cast(),
                &mut sid_string
            ),
            0
        );
        let mut length = 0;
        while *sid_string.add(length) != 0 {
            length += 1;
        }
        let sid = String::from_utf16(std::slice::from_raw_parts(sid_string, length)).unwrap();
        LocalFree(sid_string.cast());
        LocalFree(descriptor);
        assert_eq!(
            sid, "S-1-3-4",
            "only the Owner Rights SID may read the vault"
        );
        assert_ne!(
            control & SE_DACL_PROTECTED,
            0,
            "parent ACL inheritance must be disabled"
        );
    }
    assert_eq!(fs::read_dir(&scratch.dir).unwrap().count(), 2);
}
