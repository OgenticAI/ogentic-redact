<!--
Title format: <type>(OGE-XXX): short summary
  e.g. feat(OGE-484): Cargo workspace skeleton + OSS hygiene

Allowed types: feat, fix, docs, refactor, test, chore, perf, build, ci, revert
Conventional Commits is enforced — see .commitlintrc.json.
-->

Fixes [OGE-XXX](https://linear.app/ogenticai/issue/OGE-XXX). <!-- one line on where this stands -->

## What changed

<!-- The user-visible diff. What does a reader of the changelog need to know? -->

## How it works

<!-- The implementation. Mention any non-obvious invariant, locking, or ordering. -->

## Files

<!-- Group by area. Skip if the file list is small and self-explanatory. -->

## Verified locally

- [ ] `cargo build --workspace`
- [ ] `cargo test --workspace --all-features`
- [ ] `cargo clippy --workspace --all-targets -- -D warnings`
- [ ] `cargo fmt --all -- --check`
- [ ] `maturin develop && pytest python/tests` (if Python bindings touched)

## Security checklist

- [ ] No new `unsafe` blocks (or each new block has a `// SAFETY:` comment).
- [ ] No PII / raw redaction payloads in logs or error messages.
- [ ] On-device constraint respected: no network calls in the default redaction path.

## Reviewer notes

<!-- Anything the reviewer should look at first, or known follow-ups deferred to a separate ticket. -->
