# Contributing to ogentic-redact

Thanks for your interest in contributing. This is an Apache-2.0 licensed project; by submitting a contribution you agree to license your work under the same terms.

## Ground rules

- **Be kind.** See [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md).
- **Security issues do not go in public issues.** See [`SECURITY.md`](SECURITY.md).
- **On-device by default.** Any change that introduces a network call in the default redaction path requires explicit discussion and a CLAUDE.md rule update before code review.
- **Tests are not optional.** New functionality lands with unit tests or property-based tests. The library is sold on privacy guarantees — tests are the proof.

## Project layout

```
crates/
  ogentic-redact-core/       Rust library: redaction engine, entity detection, streaming pipeline
  ogentic-redact-cli/        ogentic-redact CLI binary
  ogentic-redact-rules/      Rule-pack loader and format (optional dep)
python/
  ogentic-redact-py/         PyO3 binding crate
  ogentic_redact/            Python source package
packages/
  ogentic-redact-node/       Node.js bindings (napi-rs)
swift/
  OgenticRedact/             Swift bindings (Rust → C → Swift bridge)
docs/
  architecture.md            System diagram and service boundaries
  runbooks/                  Operational runbooks
```

## Development

Prerequisites:

- Rust stable (`rustup show`) and `rustfmt` + `clippy`
- Python 3.11+ for the bindings
- [`maturin`](https://www.maturin.rs/) for building the Python wheel locally

Common commands:

```sh
cargo build --workspace
cargo test  --workspace --all-features
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check

# Build + install Python bindings into the active venv
maturin develop --release
pytest python/tests
```

## Branching and commits

- Branch off `main`. Naming: `david/oge-XXX-short-slug` for tracked work.
- Commits follow [Conventional Commits](https://www.conventionalcommits.org/). Types: `feat`, `fix`, `docs`, `refactor`, `test`, `chore`, `perf`, `build`, `ci`. Tie to a Linear ticket where applicable: `feat(OGE-XXX): short summary`.

## Pull requests

- Open against `main`. The PR template covers the required sections — fill all of them.
- Required for merge: green CI (when it lands in Q3), one approving review.

## Reporting bugs

Use the issue templates under `.github/ISSUE_TEMPLATE/`. For privacy or data-handling findings, follow [`SECURITY.md`](SECURITY.md) instead — do not open a public issue.
