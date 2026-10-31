"""Redactor — core redaction engine for ogentic-redact."""

from __future__ import annotations

import hashlib
import json
import logging
import math
import os
import re
import warnings
from collections import Counter
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from ogentic_redact._restoration import (
    DEFAULT_MAX_OUTPUT_BYTES,
    DEFAULT_MAX_REPLACEMENTS,
    restore_mapping,
    validate_restoration_input,
)
from ogentic_redact.audit import AuditDetectionEvent, AuditEmitter
from ogentic_redact.classifier import DEFAULT_MIN_CONFIDENCE
from ogentic_redact.errors import AuditError, ClassifierError, MappingNotFound
from ogentic_redact.logging import log_structured
from ogentic_redact.span import Span

if TYPE_CHECKING:
    from ogentic_redact.classifier import ClassifierProtocol
    from ogentic_redact.stores import MappingStore

_cloud_warned: bool = False


@dataclass
class RedactResult:
    """Result of a single :meth:`Redactor.redact` call.

    Attributes:
        text: The redacted text.
        vault: Deprecated. Kept for backwards compatibility; always empty in reversible mode.
        mapping_id: Opaque identifier for retrieving mapping from vault.
            Only set when :class:`Redactor` was constructed with ``reversible=True``.
    """

    text: str
    vault: dict[str, str] = field(default_factory=dict)
    mapping_id: str | None = None


class Redactor:
    """Redact sensitive spans from text.

    Two modes are supported:

    * **One-way** (default): each span is replaced with a bracketed entity
      label, e.g. ``[EMAIL]``.  The original value cannot be recovered.
    * **Reversible** (``reversible=True``): each span is replaced with a
      salted opaque token with a 128-bit discriminator, and the mapping is
      stored in a separate MappingStore. An opaque mapping_id is returned; the
      original plaintext mapping is never returned inline.

    Classifier (ADR-0002 / OGE-1230):
        Redact does not detect entities — it applies policy to spans produced by
        a classifier. Inject one via ``Redactor(classifier=...)``; when
        :meth:`redact` is called without ``spans``, they are sourced from the
        classifier (e.g. :class:`~ogentic_redact.classifier.ShieldAdapter`) and
        filtered by ``min_confidence``. With no classifier and no spans, nothing
        is redacted. The core depends only on
        :class:`~ogentic_redact.classifier.ClassifierProtocol`.

    Cloud recognisers:
        Caller-supplied spans are processed locally. Injected classifiers own
        their network behavior; ``cloud=False`` does not sandbox them. The
        compatibility ``cloud=True`` flag emits a first-use warning but does
        not configure a recogniser. ShieldAdapter is an explicit HTTP path.

    Audit:
        When an ``audit_emitter`` is passed to :meth:`redact`, one audit
        detection event is emitted per detected entity type. Emission is
        fail-closed: if the emitter raises, redaction raises :class:`AuditError`
        rather than silently completing without an audit record.

    Salt semantics:
        A fresh 128-bit random salt is generated on every :meth:`redact`
        call, so the same value produces *different* tokens across calls.
        Within a single call the salt is fixed, so the same value always
        maps to the same token (within-call stability).
    """

    def __init__(
        self,
        reversible: bool = False,
        mapping_store: MappingStore | None = None,
        cloud: bool = False,
        classifier: ClassifierProtocol | None = None,
        min_confidence: float = DEFAULT_MIN_CONFIDENCE,
    ) -> None:
        if (
            isinstance(min_confidence, bool)
            or not isinstance(min_confidence, (int, float))
            or not math.isfinite(min_confidence)
            or not 0.0 <= min_confidence <= 1.0
        ):
            raise ValueError("min_confidence must be a finite number in [0, 1]")
        self.reversible = reversible
        self.cloud = cloud
        self.mapping_store = mapping_store
        # Classifier boundary (ADR-0002 / OGE-1230): when set and no spans are
        # passed to redact(), spans are sourced from this classifier instead of
        # being detected here. The core depends only on the protocol.
        self.classifier = classifier
        self.min_confidence = min_confidence
        if reversible and mapping_store is None:
            from ogentic_redact.stores import InProcessMappingStore

            self.mapping_store = InProcessMappingStore()

    def redact(
        self,
        text: str,
        spans: list[Span] | None = None,
        matter_id: str = "",
        audit_emitter: AuditEmitter | None = None,
        tenant_id: str = "",
        request_id: str = "",
        profile: str = "default",
    ) -> RedactResult:
        """Redact *spans* from *text*.

        Args:
            text: Source string to redact.
            spans: Entity spans to replace.  Overlapping spans are resolved
                before replacement; see :meth:`resolve_overlaps`. When ``None``
                and a ``classifier`` was injected, spans are sourced from the
                classifier for *text* under *profile* (Shield classifies, Redact
                applies policy — spans below ``min_confidence`` are dropped).
                When ``None`` with no classifier, nothing is redacted.
            matter_id: Tenant/matter identifier for vault scoping. Defaults to
                empty string for single-tenant scenarios.
            audit_emitter: Optional audit event emitter. If provided, an audit
                detection event is emitted for each detected entity type. If
                audit emission fails, redaction raises :class:`AuditError`
                (fail-closed).
            tenant_id: Tenant identifier for audit context.
            request_id: Request identifier for audit context.
            profile: Profile name (e.g. "shield-legal", "default") for audit
                context.

        Returns:
            A :class:`RedactResult` with the redacted text and, in reversible
            mode, the opaque mapping_id (never the plaintext vault).

        Raises:
            TypeError: If *text* is not a :class:`str`.
            ValueError: If any span has ``start < 0``, ``end > len(text)``,
                or ``start >= end``, or if vault storage fails.
            AuditError: If *audit_emitter* is provided and event emission fails
                (fail-closed).
        """
        if not isinstance(text, str):
            raise TypeError(f"text must be str, got {type(text).__name__!r}")
        if spans is not None and not isinstance(spans, list):
            raise ValueError("spans must be a list of Span objects")

        if self.cloud:
            global _cloud_warned
            if not _cloud_warned:
                warnings.warn(
                    "Cloud-assisted classification was requested. Injected classifiers "
                    "may send sensitive data to external services. This flag does not "
                    "configure or sandbox classifiers; use a trusted local classifier "
                    "or supply spans for local-only processing.",
                    UserWarning,
                    stacklevel=2,
                )
                _cloud_warned = True

        # Span source (ADR-0002): explicit caller spans win; otherwise pull from
        # the injected classifier; otherwise redact nothing. Redact never detects.
        if spans is None and self.classifier is not None:
            spans = self._classify_spans(text, profile)
        else:
            spans = spans or []

        for span in spans:
            if not isinstance(span, Span):
                raise ValueError("spans must contain Span objects")
            if (
                type(span.start) is not int
                or type(span.end) is not int
                or type(span.group) is not int
                or span.start < 0
                or span.end > len(text)
                or span.start >= span.end
            ):
                raise ValueError(
                    "Invalid span coordinates or precedence"
                )
            if not isinstance(span.entity_type, str) or not re.fullmatch(
                r"[A-Za-z][A-Za-z0-9_]{0,127}", span.entity_type
            ):
                raise ValueError("Invalid span entity type")

        resolved = self.resolve_overlaps(spans)

        # Audit counts, in document order. `resolved` is sorted by start
        # ascending, so a Counter over it preserves first-occurrence order —
        # the replacement loop below runs right-to-left and must not be used
        # for ordering.
        entity_counts: dict[str, int] = Counter(span.entity_type for span in resolved)

        # Per-call salt: ensures tokens differ across independent calls.
        salt = os.urandom(16).hex()

        vault_dict: dict[str, str] = {}
        # Within-call stability: same (value, entity_type) → same token.
        _seen: dict[tuple[str, str], str] = {}
        source_text = text

        # Replace right-to-left so earlier indices stay valid.
        for span in sorted(resolved, key=lambda s: s.start, reverse=True):
            value = text[span.start : span.end]

            if self.reversible:
                key = (value, span.entity_type)
                if key not in _seen:
                    digest = hashlib.sha256(
                        json.dumps([salt, value, span.entity_type]).encode()
                    ).hexdigest()[:32]
                    token = f"[RTKN_{digest}]"
                    # Never turn pre-existing token-shaped source text into an
                    # accidental reference, or overwrite another mapped value.
                    collision = 0
                    while token in source_text or token in vault_dict:
                        collision += 1
                        token = f"[RTKN_{digest}{collision:08x}]"
                    _seen[key] = token
                    vault_dict[token] = value
                else:
                    token = _seen[key]
            else:
                token = f"[{span.entity_type}]"

            text = text[: span.start] + token + text[span.end :]

        mapping_id = None
        if self.reversible:
            # Invariant: reversible mode always has a vault (see __init__).
            assert self.mapping_store is not None
            try:
                mapping_id = self.mapping_store.store(vault_dict, matter_id)
            except Exception:
                raise ValueError("MappingStore storage failed (details hidden)") from None

        result = RedactResult(text=text, vault={}, mapping_id=mapping_id)

        if audit_emitter is not None:
            mode = "reversible" if self.reversible else "one-way"
            for entity_type, count in entity_counts.items():
                event = AuditDetectionEvent(
                    entity_type=entity_type,
                    mode=mode,
                    profile=profile,
                    count=count,
                    mapping_id=mapping_id,
                    tenant_id=tenant_id,
                    request_id=request_id,
                )
                try:
                    audit_emitter.emit(event)
                except Exception as e:
                    if mapping_id is not None:
                        assert self.mapping_store is not None
                        try:
                            self.mapping_store.delete(mapping_id, matter_id)
                        except MappingNotFound:
                            # An expiry/deletion during auditing already ended retention.
                            pass
                        except Exception as cleanup_error:
                            log_structured(
                                logging.ERROR,
                                "mapping rollback failed",
                                tenant_id=tenant_id,
                                request_id=request_id,
                                op="redact",
                                error_type=type(cleanup_error).__name__,
                            )
                    log_structured(
                        logging.ERROR,
                        "audit event emission failed",
                        tenant_id=tenant_id,
                        request_id=request_id,
                        op="redact",
                        entity_type=entity_type,
                        error_type=type(e).__name__,
                    )
                    raise AuditError(
                        "audit event recording failed; redaction not completed"
                    ) from None

        return result

    def _classify_spans(self, text: str, profile: str) -> list[Span]:
        """Source spans from the injected classifier, applying the confidence policy.

        Shield classifies; Redact applies policy: classified spans with
        ``confidence`` below :attr:`min_confidence` are dropped, and the rest are
        converted to internal :class:`Span` objects. Raising is left to the
        classifier (a :class:`~ogentic_redact.errors.ClassifierError` on failure).
        """
        assert self.classifier is not None  # guarded by the caller
        classified = self.classifier.classify(text, profile)
        if not isinstance(classified, list):
            raise ClassifierError("malformed classifier response")
        from ogentic_redact.classifier import RedactSpan

        for span in classified:
            if not isinstance(span, RedactSpan):
                raise ClassifierError("malformed classifier span")
            span.validate_source(text)
        return [rs.to_span() for rs in classified if rs.confidence >= self.min_confidence]

    def unredact(
        self,
        redacted_text: str,
        mapping_id: str,
        matter_id: str = "",
        *,
        consume: bool = False,
        max_output_bytes: int = DEFAULT_MAX_OUTPUT_BYTES,
        max_replacements: int = DEFAULT_MAX_REPLACEMENTS,
    ) -> str:
        """Restore original text from *redacted_text* using vault lookup.

        Args:
            redacted_text: A string previously returned by :meth:`redact`.
            mapping_id: The :attr:`RedactResult.mapping_id` from the same call.
            matter_id: Tenant/matter identifier. Must match the one passed to redact().
            consume: Atomically remove the mapping after successful restoration. Defaults
                to False so repeated responses can share a mapping until deletion
                or expiry. Unused tokens are skipped in partial LLM responses.
            max_output_bytes: Maximum restored UTF-8 bytes (default 16 MiB).
            max_replacements: Maximum mapped token occurrences (default 100,000).
                Rejected restoration leaves the mapping available.

        Returns:
            The original text with all tokens substituted back.

        Raises:
            ValueError: If the :class:`Redactor` was not created with
                ``reversible=True``, or if mapping_id is not found under matter_id,
                or if vault access fails.
            TypeError: If *redacted_text* is not a :class:`str`.
        """
        if not self.reversible:
            raise ValueError("unredact() requires Redactor(reversible=True)")
        validate_restoration_input(redacted_text, max_output_bytes, max_replacements)

        # Invariant: reversible mode always has a vault (see __init__).
        assert self.mapping_store is not None
        try:
            vault_dict = self.mapping_store.fetch(mapping_id, matter_id)
        except Exception:
            raise ValueError("Unable to restore mapping: unavailable, unknown or expired") from None

        restored = restore_mapping(
            redacted_text, vault_dict,
            max_output_bytes=max_output_bytes, max_replacements=max_replacements,
        )
        if consume:
            try:
                # IDs identify immutable records. Only the successful atomic
                # consumer may return a result, even if several callers fetched.
                consumed = self.mapping_store.consume(mapping_id, matter_id)
                if consumed != vault_dict:
                    raise ValueError("mapping changed during restoration")
            except Exception:
                raise ValueError("Unable to restore mapping: unavailable, unknown or expired") from None
        return restored

    @staticmethod
    def resolve_overlaps(spans: list[Span]) -> list[Span]:
        """Protect the union of each connected group of overlapping spans.

        Every detected character remains covered. Each region takes its label
        from the span ranked first by lower group number, earlier start, longer
        length, then entity type. Label selection uses the original spans and
        is independent of their input order. Adjacent spans remain separate.

        Args:
            spans: Arbitrary collection of :class:`Span` objects.

        Returns:
            Non-overlapping protected regions sorted by start. A merged region
            counts as one redaction and, in reversible mode, stores its complete
            original substring so restoration preserves the exact input.
        """
        if not spans:
            return []

        def priority(span: Span) -> tuple[int, int, int, str]:
            return span.group, span.start, -(span.end - span.start), span.entity_type

        ordered = sorted(spans, key=lambda span: (span.start, span.end))
        winner = ordered[0]
        start, end = winner.start, winner.end
        resolved: list[Span] = []
        for span in ordered[1:]:
            if span.start >= end:
                resolved.append(Span(start, end, winner.entity_type, winner.group))
                start, end, winner = span.start, span.end, span
                continue
            end = max(end, span.end)
            if priority(span) < priority(winner):
                winner = span
        resolved.append(Span(start, end, winner.entity_type, winner.group))
        return resolved
