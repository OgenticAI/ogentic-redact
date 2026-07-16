"""Streaming redaction over audio-transcript chunk iterables.

Backs Sotto Desktop Meeting Mode (step 2 live redaction — OGE-1221).
"""

from __future__ import annotations

from collections.abc import Generator, Iterable
from typing import TYPE_CHECKING

from presidio_analyzer import AnalyzerEngine
from presidio_analyzer.nlp_engine import NlpEngineProvider

from ogentic_redact.audit import DetectionEvent
from ogentic_redact.profile import Profile

if TYPE_CHECKING:
    from presidio_analyzer import RecognizerResult

__all__ = ["redact_stream"]

# Number of trailing characters kept from the previous chunk to detect entities
# that span a chunk boundary.  120 chars covers the longest common PII spans.
_TAIL_CHARS = 120

# Module-level singleton so the heavy spaCy model is loaded only once.
_analyzer: AnalyzerEngine | None = None


def _get_analyzer() -> AnalyzerEngine:
    """Return the module-level AnalyzerEngine, creating it on first call."""
    global _analyzer
    if _analyzer is None:
        provider = NlpEngineProvider(nlp_configuration={
            "nlp_engine_name": "spacy",
            "models": [{"lang_code": "en", "model_name": "en_core_web_sm"}],
        })
        _analyzer = AnalyzerEngine(nlp_engine=provider.create_engine())
    return _analyzer


def _build_token(entity_type: str, counters: dict[str, int]) -> str:
    """Return the next ``<<ENTITY_TYPE_N>>`` token for *entity_type*."""
    n = counters.get(entity_type, 0) + 1
    counters[entity_type] = n
    return f"<<{entity_type}_{n}>>"


def _apply_substitutions(text: str, spans: list[tuple[int, int, str]]) -> str:
    """Replace *spans* in *text* with their token strings.

    Spans are ``(start, end, token)`` and must be non-overlapping.
    They are applied right-to-left so offsets remain valid.
    """
    result = text
    for start, end, token in sorted(spans, key=lambda s: s[0], reverse=True):
        result = result[:start] + token + result[end:]
    return result


def redact_stream(
    chunks: Iterable[str],
    profile: Profile,
) -> Generator[tuple[str, list[DetectionEvent]], None, None]:
    """Yield ``(redacted_chunk, events)`` pairs for each input chunk.

    The generator is on-device — it makes no network calls. Entity detection
    uses Presidio with a local spaCy model. Entities that span a chunk boundary
    are captured via a sliding tail buffer and fully redacted in the chunk where
    they *end*.

    Token format follows OGE-1200 (REDACT-R1): ``<<ENTITY_TYPE_N>>``.

    Args:
        chunks: Iterable of raw transcript-chunk strings.
        profile: Specifies which entity types to detect and the language code.

    Yields:
        A ``(redacted_chunk, events)`` tuple for every input chunk.  ``events``
        is a (possibly empty) list of :class:`DetectionEvent` objects describing
        each detection in the *original* chunk coordinate space.
    """
    analyzer = _get_analyzer()
    entity_counters: dict[str, int] = {}
    tail = ""

    for chunk_index, chunk in enumerate(chunks):
        combined = tail + chunk
        tail_len = len(tail)

        results: list[RecognizerResult] = analyzer.analyze(
            text=combined,
            entities=profile.entity_types,
            language=profile.language,
        )

        # Sort by start so substitutions can be processed cleanly.
        results.sort(key=lambda r: r.start)

        # Deduplicate overlapping spans (keep highest-score span).
        deduped: list[RecognizerResult] = []
        last_end = -1
        for res in results:
            if res.start < last_end:
                # Overlapping with previous; keep higher score.
                if res.score > deduped[-1].score:
                    deduped[-1] = res
                continue
            deduped.append(res)
            last_end = res.end

        # Split into:
        #   • skip_spans  — entirely within the tail (already handled or not ours)
        #   • apply_spans — overlap with the current chunk (boundary or local)
        chunk_substitutions: list[tuple[int, int, str]] = []
        events: list[DetectionEvent] = []

        for res in deduped:
            if res.end <= tail_len:
                # Entirely in the tail — skip (previous chunk handled it or it
                # exists only in the tail padding).
                continue

            # Compute the portion of this span that falls within *chunk*.
            chunk_start = max(res.start - tail_len, 0)
            chunk_end = res.end - tail_len  # always > 0 given the filter above

            # Assign a token (shared counter across chunks for consistency).
            token = _build_token(res.entity_type, entity_counters)
            chunk_substitutions.append((chunk_start, chunk_end, token))
            events.append(
                DetectionEvent(
                    entity_type=res.entity_type,
                    chunk_index=chunk_index,
                    start=chunk_start,
                    end=chunk_end,
                    score=res.score,
                )
            )

        redacted_chunk = _apply_substitutions(chunk, chunk_substitutions)

        # Update the tail for the *next* iteration (use the original chunk so
        # boundary detection in the next chunk works against original offsets).
        tail = chunk[-_TAIL_CHARS:] if len(chunk) > _TAIL_CHARS else chunk

        yield redacted_chunk, events
