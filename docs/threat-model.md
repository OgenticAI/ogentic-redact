# ogentic-redact — Threat Model & Privacy Guarantees

**Taxonomy reference:** REDACT-F4
**Depends on:** REDACT-F2 (reversible-mode vault design)
**Last updated:** 2026-07-17
**Status:** Authoritative for v0.1

---

## 1. Overview

`ogentic-redact` provides real-time, on-device sensitive-content redaction. It operates in one of two modes with fundamentally different threat surfaces:

| Property | One-way (default) | Reversible |
|---|---|---|
| Mapping persisted | No | Yes — vault file |
| Re-identification possible | No | Yes — requires vault |
| Network egress | None (default) | None (default); `[cloud]` opt-in only |
| Suitable for | Maximum cloud privacy | Round-trip restore workflows |

This document enumerates what `ogentic-redact` guarantees in each mode, the residual risks in each, and — critically — what the library does **not** promise.

---

## 2. One-way (lossy) mode — guarantees & threat surface

### Guarantees

- **No mapping is persisted.** The token-to-original mapping is computed in-process and discarded immediately after the redacted text is emitted. No file is written, no in-memory store is retained past the call boundary.
- **Redaction is irreversible by construction.** There is no API surface that can restore the original tokens after a one-way call completes. The library does not retain state between calls.
- **Maximum cloud privacy.** Text forwarded to any downstream system (LLM, logging pipeline, third-party API) after a one-way redaction contains no tokens that can be reversed, even by an adversary who compromises the calling process after the call returns.

### Threat surface

- **In-flight interception.** If the original text is transmitted over a network before redaction, the redaction itself does not protect it. Callers are responsible for ensuring redaction happens before any network boundary.
- **Recognised-entity gaps.** One-way mode can only redact entities that the active recogniser detects. Unknown entity types, novel PII patterns, or deliberately obfuscated content may pass through un-redacted. See §8 (Non-guarantees).
- **Process memory during the call.** The original text and the computed mapping both exist in process memory for the duration of the redaction call. A memory-dump attack against the calling process during that window could recover them. This is not a library-level guarantee and is out of scope for v0.1.
- **Side-channel leakage via token shape.** Replacement tokens (e.g., `<PERSON_0>`, `<EMAIL_1>`) reveal the category and count of detected entities. An adversary with access to the redacted output can infer entity structure. This is by design and documented as a non-guarantee (§8).

---

## 3. Reversible (tokenised) mode — guarantees & threat surface

Reversible mode is activated explicitly by the caller:

```python
redactor = Redactor(reversible=True)
result = redactor.redact(text)
# result.redacted:    redacted text
# result.mapping_id:  opaque identifier — never the mapping itself
```

### Guarantees

- **The mapping is never inlined in the response.** `result.mapping_id` is an opaque identifier; the actual token-to-original table is written to the vault only. This maintains the two-phase design even under error conditions — partial results never expose the mapping inline.
- **Vault is the sole re-identification artifact.** Without the vault, the redacted text produced by reversible mode is as irreversible as one-way mode. Reversibility depends entirely on vault availability.
- **Caller owns vault protection.** The library writes the vault and returns the path / identifier. Protection (filesystem permissions, encryption at rest, key management) is the caller's responsibility. See §4.

### Threat surface

- **Vault compromise equals re-identification.** Any party that obtains the vault and the corresponding redacted text can restore the original. The vault is a high-value target.
- **Vault identifier guessability.** If `mapping_id` values are predictable (sequential integers, weak UUIDs), an adversary with partial access to the vault store can enumerate and retrieve mappings. Implementations must use cryptographically random identifiers.
- **Vault persistence increases exposure window.** Unlike one-way mode, the mapping survives the call. Every second the vault exists is a window for exfiltration. Callers should apply a retention policy (TTL, explicit delete after restore).
- **Multi-tenant vault leakage.** In server-side deployments with a shared vault store, `mapping_id` values must be scoped per-tenant. A `mapping_id` issued for `tenant_id=A` must return an error — not the wrong vault — when presented under `tenant_id=B`. See `docs/redact-demo-design.md` §6.

---

## 4. The vault: sole re-identification artifact

The vault is the only artifact that can re-identify redacted content in reversible mode. This section states caller obligations explicitly.

**What the vault contains:**
A mapping from replacement tokens (e.g., `<PERSON_0>`) back to the original values (e.g., `"Jane Smith"`). In the local-file persistence model, this is a JSON file. In a server-side store, it is a keyed record.

**Caller obligations:**
1. **Access control.** Treat the vault file with the same access controls as the original PII. If the original data is classified, the vault is classified at the same level.
2. **Encryption at rest.** The library does not encrypt the vault. Callers operating in environments with encryption-at-rest requirements must apply encryption themselves (filesystem-level or application-level).
3. **Retention limits.** Delete the vault when the round-trip is complete or when the retention window expires. The library provides no automatic TTL enforcement in v0.1.
4. **Backup exclusion.** Exclude vault files from backup systems unless those backups have equivalent access controls to the original PII.
5. **Audit trail.** If your threat model requires it, log vault creation, access, and deletion events. The library will emit structured log events with `op=vault_write` and `op=vault_read` (planned for the Wave 2 implementation) but will not enforce audit logging.

**What happens if the vault is lost:**
The redacted text becomes permanently irreversible. There is no recovery mechanism. Treat vault loss the same way you treat encryption key loss.

---

## 5. Per-call salt: defence & residual risks

In reversible mode, a fresh cryptographically random salt is generated for each `redact()` call. The salt is incorporated into the vault identifier and (where applicable) into token generation.

### What the salt defends against

- **Token-reversal via rainbow table.** Without per-call salt, an adversary who observes many redacted outputs could build a lookup table mapping replacement tokens back to common PII values (e.g., mapping `<EMAIL_0>` across many documents to find repeated addresses). Per-call salt makes this attack computationally infeasible: a separate table would be needed for every individual call.
- **Cross-call correlation.** If the same PII value appeared in two separate `redact()` calls and produced the same token, an adversary could correlate the two outputs to infer they share a common underlying value. Per-call salt breaks this correlation — the same input value will (with overwhelming probability) produce a different token in each call.

### Residual risks

- **Within-call correlation is intentional.** The same PII value appearing multiple times in a single `redact()` call receives the same replacement token (e.g., all occurrences of `"Jane Smith"` become `<PERSON_0>`). This is a deliberate feature (it preserves readability) but it means intra-document co-occurrence analysis is still possible.
- **Salt is not a key.** The salt is not a secret. It is stored in the vault alongside the mapping. An adversary with vault access gains the salt. The salt's purpose is to defeat cross-call attacks, not to act as a confidentiality mechanism.
- **Salt entropy depends on the PRNG.** The library uses the platform's cryptographically secure random number generator. In environments where the CSPRNG is compromised (e.g., a VM with insufficient entropy at boot), salt uniqueness may be weakened. This is an infrastructure concern outside the library's scope.
- **No salt in one-way mode.** One-way mode discards both the salt and the mapping immediately. Salt is irrelevant to one-way mode's threat model.

---

## 6. On-device boundary: what stays on-device

`ogentic-redact` is on-device by default. This section defines what "on-device" means and where the boundary is.

### What runs on-device (always)

- Named-entity recognition (NER) using the bundled model or a caller-supplied model.
- Rule-pack evaluation (regex, keyword, and custom rules from `ogentic-redact-rules`).
- Token generation and replacement.
- Vault write (local filesystem path).
- All `Redactor` core logic.

### What requires the `[cloud]` extra

Cloud-assisted recognisers are an opt-in feature:

```
pip install 'ogentic-redact[cloud]'
```

When any cloud recogniser is active, the library emits a one-time runtime warning:

```
[ogentic-redact] WARNING: cloud recogniser active — text will leave this device.
```

This warning fires once per process, not per call, to avoid log spam. It cannot be suppressed. The intent is to make cloud egress visible in logs even when enabled deliberately.

### Trust boundary

The trust boundary is the local process. Anything within the process (including the caller's own code) is trusted; anything outside (network, filesystem accessible by other users, shared memory) is not.

This means:
- The library does not protect against a compromised caller.
- The library does not protect against OS-level privilege escalation.
- The library does not protect text after it leaves the `redact()` call return value — caller code that logs `result.redacted` without further scrubbing is responsible for that log's security posture.

---

## 7. `[cloud]` opt-in: egress path and trust implications

When a cloud recogniser is active, some or all of the input text may be sent to a remote endpoint for entity detection. The following trust implications apply:

1. **Text leaves the device.** The portion of text analysed by the cloud recogniser is transmitted over the network to a third-party or OgenticAI-operated endpoint. This text may contain un-redacted PII if cloud recognition is used as the first pass.
2. **The remote endpoint's privacy posture is external to this library.** `ogentic-redact` makes no guarantees about the remote endpoint's data retention, logging, or jurisdiction. Review the endpoint's privacy policy separately.
3. **Cloud recognisers are additive.** Cloud recognisers run alongside on-device recognisers and contribute additional entity detections. They do not replace the on-device pass.
4. **Disabling cloud recognition.** Remove the `[cloud]` extra from the installation, or do not configure a cloud recogniser in the `Redactor` constructor. Absence of configuration is the only supported way to guarantee no cloud egress.

---

## 8. Non-guarantees (explicit)

The following are things `ogentic-redact` does **not** promise. These are not bugs; they are explicit scope boundaries.

| Non-guarantee | Explanation |
|---|---|
| **Complete PII coverage** | The library detects entities the active recogniser knows about. Novel PII types, deliberately obfuscated content, or entities below the confidence threshold will pass through un-redacted. |
| **Semantic anonymisation** | Replacing a name with `<PERSON_0>` does not guarantee k-anonymity or differential privacy. Quasi-identifier combinations (age + zip + occupation in a narrow dataset) can still re-identify individuals after token replacement. |
| **Network-level confidentiality** | If the caller transmits the original text over a network before calling `redact()`, the library cannot retroactively protect that transmission. |
| **Vault encryption** | The vault is written as plaintext JSON by default. The library does not encrypt it. Callers with encryption-at-rest requirements must apply encryption externally. |
| **Side-channel resistance** | Token shape (category + count) is visible in the redacted output by design. Timing side-channels and memory side-channels in the NER model are out of scope. |
| **Model adversarial robustness** | An adversary who can craft inputs designed to evade the NER model (adversarial examples) may succeed in passing PII through un-redacted. Adversarial robustness of the underlying model is out of scope for v0.1. |
| **Multi-tenant isolation in v0.1** | The v0.1 library is designed for single-process, single-tenant use. Server-side multi-tenant deployments that share a vault store must implement their own tenant-scoping; the library does not enforce it. |
| **Compliance certification** | This document describes the library's technical guarantees. It is not a compliance certification (SOC 2, HIPAA, GDPR adequacy, etc.). Compliance determinations require organisational controls beyond the scope of a software library. |

---

## 9. Relationship to sibling libraries

| Library | Redaction style | Mapping | Threat profile |
|---|---|---|---|
| `ogentic-shield` | One-way + inline mapping | Returned in the response payload | Mapping is ephemeral; caller owns retention |
| `ogentic-redact` (one-way) | One-way, no mapping | Discarded | Maximum cloud privacy; no re-identification possible |
| `ogentic-redact` (reversible) | Two-phase vault | Stored separately, referenced by opaque ID | Vault is the sole re-identification artifact |
| `ogentic-audit` | Append-only audit log | N/A | Immutability guarantee; separate threat model |

`ogentic-shield`'s inline mapping is appropriate when the caller needs immediate restore capability and accepts responsibility for the mapping's lifetime. `ogentic-redact`'s vault model is appropriate when the caller wants the redacted text and the mapping to be physically separated, reducing the blast radius of a redacted-text leak to zero re-identification risk.

---

## 10. Future work / open questions

- **Vault encryption (built-in).** A `[vault-enc]` extra that encrypts the vault with a caller-supplied key or auto-generated key-encryption-key is planned but not in v0.1 scope.
- **Vault TTL enforcement.** Automatic vault expiry with a configurable retention window is a Wave 3 target.
- **Differential privacy.** Adding ε-DP noise to numerical entities (ages, salaries, zip codes) is an open research question; not committed for any release.
- **REDACT-F2 cross-reference.** The vault format and `mapping_id` scheme are specified in REDACT-F2. This document assumes that design is stable; updates to REDACT-F2 may require corresponding updates here.
