//! `ogentic-redact` CLI — forward redaction with a separate mapping vault, and
//! reverse restoration from that vault (OGE-1266, demo-design §2).
//!
//! ```text
//! ogentic-redact <input> --mapping vault.json              # redact → stdout, vault → file
//! ogentic-redact unredact <redacted> --mapping vault.json  # restore → stdout
//! ```
//!
//! **On-device by default.** Detection is the core byte-scanner (EMAIL / PHONE /
//! US_SSN) — a documented development convenience; production spans come from
//! `ogentic-shield` (ADR-0002). No network calls are made on the default path.
//! `--cloud` opts in to cloud-assisted recognisers and emits a first-use runtime
//! warning; it does not yet change detection (that path lands with OGE-1230).
//!
//! The mapping vault is written to `--mapping <file>` and is **never** inlined
//! into the redacted stdout. A `redact` then `unredact` round-trip reproduces the
//! input byte-for-byte.

use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use ogentic_redact_core::{redact_one_way, unredact_one_way};
use serde::{Deserialize, Serialize};

/// Grammar version stamped into freshly written mapping files. Matches the
/// conformance vector suite (`conformance/vectors.json`).
const MAPPING_VERSION: &str = "f4";

#[derive(Parser)]
#[command(
    name = "ogentic-redact",
    version,
    about = "On-device sensitive-content redaction with a reversible mapping vault",
    long_about = None,
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,

    /// Input file to redact, or `-` to read from stdin.
    #[arg(value_name = "INPUT")]
    input: Option<String>,

    /// Write the reversible mapping vault to this JSON file. When omitted, the
    /// redaction is one-way and no vault is produced.
    #[arg(long, value_name = "FILE")]
    mapping: Option<PathBuf>,

    /// Opt in to cloud-assisted recognisers (emits a first-use runtime warning).
    #[arg(long)]
    cloud: bool,
}

#[derive(Subcommand)]
enum Command {
    /// Restore original text from a redacted file using its mapping vault.
    Unredact {
        /// Redacted input file, or `-` to read from stdin.
        #[arg(value_name = "REDACTED")]
        input: String,

        /// Mapping vault JSON written by a prior redaction.
        #[arg(long, value_name = "FILE")]
        mapping: PathBuf,
    },
}

/// On-disk mapping vault: a versioned `token → original` table.
///
/// Written by forward redaction and consumed by `unredact`. Kept deliberately
/// separate from the redacted output — the vault is never inlined into stdout.
#[derive(Serialize, Deserialize)]
struct MappingFile {
    /// Token grammar version (see `conformance/vectors.json`).
    version: String,
    /// Token → original value. `BTreeMap` keeps the file order stable across runs.
    tokens: BTreeMap<String, String>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Some(Command::Unredact { input, mapping }) => run_unredact(&input, &mapping),
        None => {
            let input = cli
                .input
                .as_deref()
                .context("no input given; usage: ogentic-redact <input> --mapping <out.json>")?;
            run_redact(input, cli.mapping.as_deref(), cli.cloud)
        },
    }
}

/// Forward redaction: redacted text to stdout, mapping vault to `mapping` (if any).
fn run_redact(source: &str, mapping: Option<&Path>, cloud: bool) -> Result<()> {
    if cloud {
        warn_cloud_once();
    }

    let text = read_input(source)?;
    let result = redact_one_way(&text);

    if let Some(path) = mapping {
        let file = MappingFile {
            version: MAPPING_VERSION.to_owned(),
            tokens: result.tokens.into_iter().collect(),
        };
        let json =
            serde_json::to_string_pretty(&file).context("failed to serialise mapping vault")?;
        fs::write(path, json).with_context(|| format!("failed to write mapping vault {path:?}"))?;
    }

    write_stdout(&result.text)
}

/// Reverse redaction: restore the original text from `mapping` and print it.
fn run_unredact(source: &str, mapping: &Path) -> Result<()> {
    let redacted = read_input(source)?;
    let raw = fs::read_to_string(mapping)
        .with_context(|| format!("failed to read mapping vault {mapping:?}"))?;
    let file: MappingFile = serde_json::from_str(&raw)
        .with_context(|| format!("mapping vault {mapping:?} is not valid JSON"))?;

    let tokens: HashMap<String, String> = file.tokens.into_iter().collect();
    let restored = unredact_one_way(&redacted, &tokens);
    write_stdout(&restored)
}

/// Read all of `source` (a file path, or `-` for stdin) as a UTF-8 string.
fn read_input(source: &str) -> Result<String> {
    if source == "-" {
        let mut buf = String::new();
        io::stdin()
            .read_to_string(&mut buf)
            .context("failed to read from stdin")?;
        Ok(buf)
    } else {
        fs::read_to_string(source).with_context(|| format!("failed to read input file {source:?}"))
    }
}

/// Write `text` to stdout byte-exactly (no trailing newline added), so a
/// `redact` → `unredact` round-trip reproduces the input exactly.
fn write_stdout(text: &str) -> Result<()> {
    io::stdout()
        .write_all(text.as_bytes())
        .context("failed to write to stdout")
}

/// Emit the cloud opt-in warning. There is a single redaction per invocation, so
/// this fires at most once per process — the "first use" required by the AC.
fn warn_cloud_once() {
    eprintln!(
        "warning: cloud-assisted recognisers are enabled (--cloud); sensitive data \
         may be sent to external services. The built-in CLI detector remains \
         on-device only — production cloud detection is not yet wired (OGE-1230). \
         Omit --cloud to enforce on-device-only redaction."
    );
}
