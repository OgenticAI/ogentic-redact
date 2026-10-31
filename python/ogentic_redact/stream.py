"""Local redaction of a finalized record supplied in transport chunks.

A chunk boundary is not a classification boundary. No output is released until
all chunks in the record have been received, classified and (if configured)
audited. Live callers should submit one finalized utterance/record per call.
"""

from __future__ import annotations

import logging
import math
from collections import Counter
from collections.abc import Generator, Iterable
from dataclasses import dataclass
from typing import TYPE_CHECKING

import spacy
from presidio_analyzer import AnalyzerEngine
from presidio_analyzer.nlp_engine import SpacyNlpEngine

from ogentic_redact.audit import AuditDetectionEvent, AuditEmitter, DetectionEvent
from ogentic_redact.errors import AuditError, ClassifierError, RedactError
from ogentic_redact.logging import log_structured
from ogentic_redact.profile import Profile

if TYPE_CHECKING:
    from presidio_analyzer import RecognizerResult

__all__ = ["redact_stream"]

_MODEL_NAME = "en_core_web_sm"
_analyzer: AnalyzerEngine | None = None


class _OfflineSpacyEngine(SpacyNlpEngine):
    """Load only installed models; never invoke Presidio's model downloader."""

    def load(self) -> None:
        try:
            # Presidio initializes this attribute to None without annotating it.
            self.nlp = {"en": spacy.load(_MODEL_NAME)}  # type: ignore[assignment]
        except OSError:
            raise RedactError(
                "Local model en_core_web_sm is unavailable. Install it during setup "
                "with 'python -m spacy download en_core_web_sm'; runtime does not download models."
            ) from None


def _get_analyzer() -> AnalyzerEngine:
    """Return the local analyzer, with model acquisition left to explicit setup."""
    global _analyzer
    if _analyzer is None:
        _analyzer = AnalyzerEngine(nlp_engine=_OfflineSpacyEngine(
            models=[{"lang_code": "en", "model_name": _MODEL_NAME}],
        ))
    return _analyzer


@dataclass(frozen=True)
class _Detection:
    start: int
    end: int
    entity_type: str
    score: float


def _resolve_detections(results: list[RecognizerResult], text_len: int) -> list[_Detection]:
    """Protect the union of overlapping sensitive spans, never drop coverage.

    The highest-confidence detection labels each merged region. Ties are stable
    by position and entity type; adjacent non-overlapping spans stay separate.
    """
    for result in results:
        if (
            type(result.start) is not int
            or type(result.end) is not int
            or not 0 <= result.start < result.end <= text_len
            or isinstance(result.score, bool)
            or not isinstance(result.score, (int, float))
            or not math.isfinite(result.score)
            or not 0 <= result.score <= 1
            or not isinstance(result.entity_type, str)
            or not result.entity_type
        ):
            raise ClassifierError("local classifier returned an invalid span")
    ordered = sorted(results, key=lambda r: (r.start, r.end, r.entity_type))
    resolved: list[_Detection] = []
    for result in ordered:
        candidate = _Detection(result.start, result.end, result.entity_type, result.score)
        if not resolved or candidate.start >= resolved[-1].end:
            resolved.append(candidate)
            continue
        previous = resolved[-1]
        label = candidate if candidate.score > previous.score else previous
        resolved[-1] = _Detection(
            previous.start, max(previous.end, candidate.end), label.entity_type, label.score,
        )
    return resolved


def redact_stream(
    chunks: Iterable[str],
    profile: Profile,
    cloud: bool = False,
    audit_emitter: AuditEmitter | None = None,
    tenant_id: str = "",
    request_id: str = "",
    *,
    max_buffer_chars: int = 100_000,
    max_chunks: int = 4096,
) -> Generator[tuple[str, list[DetectionEvent]], None, None]:
    """Redact a finite, finalized record and yield one pair per transport chunk.

    Input is buffered until the iterable ends. This finalization is required:
    transport chunk boundaries cannot establish that an entity is complete.
    No prefix is emitted on input, classification, capacity, or audit failure.
    Live callers should invoke this function for each finalized utterance.

    Text outside detected spans is preserved exactly. A cross-chunk entity is
    replaced once in the chunk where it starts, with all remaining portions
    removed from subsequent chunks. Events describe each protected portion in
    its original chunk's coordinates; audit counts count each merged region
    once. Overlapping detections protect their entire union.

    Detection uses an installed local English spaCy model. Model installation
    is an explicit setup operation. ``cloud=True`` is unsupported; use an
    explicitly configured classifier with ``Redactor`` for that workflow.
    Every requested entity must be supported by this analyzer; unsupported
    policies raise ``ClassifierError`` before output. An explicit empty entity
    list performs no detection and does not load the model.

    ``max_buffer_chars`` and ``max_chunks`` bound pending input. Exceeding either
    raises ``RedactError`` without output. Audit events are acknowledged before
    the first result is yielded. Tokens retain the ``<<ENTITY_TYPE_N>>`` grammar.
    """
    if cloud:
        raise ValueError("redact_stream supports local detection only")
    if type(max_buffer_chars) is not int or max_buffer_chars <= 0:
        raise ValueError("max_buffer_chars must be a positive integer")
    if type(max_chunks) is not int or max_chunks <= 0:
        raise ValueError("max_chunks must be a positive integer")
    profile.validate()
    # A transport iterable must not be able to change policy during buffering.
    entity_types = list(profile.entity_types)
    language = profile.language
    buffered: list[str] = []
    length = 0
    for chunk in chunks:
        if not isinstance(chunk, str):
            raise TypeError("every chunk must be a string")
        length += len(chunk)
        if length > max_buffer_chars or len(buffered) >= max_chunks:
            raise RedactError("unfinished record exceeds the configured buffer limit")
        buffered.append(chunk)
    if not buffered:
        return

    text = "".join(buffered)
    results: list[RecognizerResult] = []
    if text and entity_types:
        try:
            analyzer = _get_analyzer()
            supported = analyzer.get_supported_entities(language=language)
            unsupported = sorted(set(entity_types).difference(supported))
            if unsupported:
                raise ClassifierError(
                    "local classifier does not support requested entities: "
                    + ", ".join(unsupported)
                    + "; use ShieldAdapter for Shield domain profiles"
                )
            results = analyzer.analyze(
                text=text, entities=entity_types, language=language,
            )
        except RedactError:
            raise
        except Exception:
            raise ClassifierError("local classification failed") from None
    try:
        resolved = _resolve_detections(results, len(text))
    except (AttributeError, TypeError, ValueError):
        raise ClassifierError("local classifier returned an invalid response") from None
    counts = Counter(result.entity_type for result in resolved)
    if audit_emitter is not None:
        for entity_type, count in counts.items():
            event = AuditDetectionEvent(
                entity_type=entity_type, mode="one-way", profile="local-stream",
                count=count, mapping_id=None, tenant_id=tenant_id, request_id=request_id,
            )
            try:
                audit_emitter.emit(event)
            except Exception:
                log_structured(
                    logging.ERROR, "audit event emission failed", tenant_id=tenant_id,
                    request_id=request_id, op="redact_stream", entity_type=entity_type,
                )
                raise AuditError("audit event recording failed; redaction not completed") from None

    counters: dict[str, int] = {}
    tokens: list[str] = []
    for result in resolved:
        number = counters.get(result.entity_type, 0) + 1
        counters[result.entity_type] = number
        tokens.append(f"<<{result.entity_type}_{number}>>")

    offset = 0
    first_span = 0
    for chunk_index, chunk in enumerate(buffered):
        if not chunk:
            yield "", []
            continue
        end = offset + len(chunk)
        cursor = offset
        parts: list[str] = []
        events: list[DetectionEvent] = []
        index = first_span
        while index < len(resolved) and resolved[index].start < end:
            result = resolved[index]
            if result.end <= offset:
                index += 1
                first_span = index
                continue
            start_in_chunk = max(result.start, offset)
            end_in_chunk = min(result.end, end)
            parts.append(text[cursor:start_in_chunk])
            if result.start >= offset:
                parts.append(tokens[index])
            events.append(DetectionEvent(
                entity_type=result.entity_type, chunk_index=chunk_index,
                start=start_in_chunk - offset, end=end_in_chunk - offset, score=result.score,
            ))
            cursor = end_in_chunk
            if result.end > end:
                break
            index += 1
            first_span = index
        parts.append(text[cursor:end])
        offset = end
        yield "".join(parts), events
