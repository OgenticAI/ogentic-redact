# CLAUDE.md — `ogentic-redact`

This file loads into every Claude Code / Claude Desktop session in this repo.
Keep it 100-300 lines. Every rule earns its place.

> **How to evolve this file:** every time Claude makes a mistake that surprises you,
> ask "would a rule here have prevented this?" If yes, add the rule.

---

## 1. What this repo is

**Name:** ogentic-redact
**One-liner:** Real-time, on-device sensitive-content redaction. The 'Redact' step in the privacy-aware AI pipeline.
**Owner:** David (CTO)
**Kind:** oss-library
**Customer-facing?** oss-library — public OSS surface or internal app per kind.

---

## 2. Stack

**Python OSS library:**
- Python 3.11+, type-hinted throughout
- Pydantic v2 for any data models
- pytest + pytest-asyncio
- ruff + mypy strict
- Extends Microsoft Presidio for entity recognition
- Published to PyPI as `ogentic-redact`

---

## 3. Commands

```
# install
# (fill in once the build system is initialised)

# run
# (fill in once the entry point exists)

# tests
# (fill in)

# typecheck + lint
# (fill in)
```

---

## 4. Architecture rules

These are non-negotiable. The validator enforces them.

**On-device only by default.**
No network calls in the default redaction path. Cloud-assisted recognisers are an opt-in extra (`[cloud]`) with a runtime warning the first time they're used.

**Reversible iff explicitly enabled.**
Redaction is one-way by default. Reversible (tokenised) mode requires `Redactor(reversible=True)` and emits a separate vault file — never inlined.

**No raw error exposure to clients.**
Catch, log with context, return a sanitised message.

**Time is UTC.**
Display-time timezone conversion happens in the UI layer only.

**LLM calls go through `ogentic_llm` (when applicable).**
Never call OpenAI/Anthropic/Google SDKs directly. The abstraction handles retries, cost tracking, and observability.

---

## 5. Don't do this

<!-- The growing list of things Claude has gotten wrong. Add rules below as Claude surprises you. -->

- **Do not** add `cron`. Use BullMQ (TS) or arq (Python).
- **Do not** log raw payment payloads, raw LLM inputs that contain user PII, or full request bodies in error logs.
- **Do not** call LLM provider SDKs directly. Use `ogentic_llm`.
- **Do not** ship a feature without acceptance tests covering at least one failure path.

---

## 6. Conventions

**Commits.** Use `feat(OGE-NNN): <subject>` to link to Linear.
**Branches.** Use the Linear branch name (`david/oge-nnn-<slug>`).
**Errors.** Domain exceptions in `errors.${ext}`; map to HTTP at the boundary.
**Logging.** Structured JSON; mandatory fields: `tenant_id`, `request_id`, `service`, `op`.

---

## 7. Factory contract

```markdown
@./.claude/CLAUDE-FACTORY.md
```

(If your Claude install doesn't handle `@file` imports, paste `.claude/CLAUDE-FACTORY.md` here inline.)

---

## 8. Pointers to deeper docs

<!-- Replace with real docs as they exist. -->

- `docs/architecture.md` — system diagram, service boundaries
- `docs/runbooks/` — what to do when it breaks

---

## 9. For the agents

Agent sign-off conventions (including the `SUMMARY` block format) live in `.claude/CLAUDE-FACTORY.md` §F3. Refer there.
