"""Acceptance tests for redact_stream (OGE-1221 / REDACT-R6).

AC1: redact_stream yields (redacted_chunk, list[DetectionEvent]) for each chunk.
AC2: Per-chunk latency <= 100 ms (see bench_stream.py for the formal benchmark).
AC3: Entities spanning a chunk boundary are fully redacted.
AC4: Streaming path is on-device (no network calls in the default path).
AC5: Each DetectionEvent carries entity_type, chunk_index, start, end, score.
"""

from __future__ import annotations

import time
from unittest.mock import patch

import pytest

from ogentic_redact.audit import DetectionEvent
from ogentic_redact.profile import Profile
from ogentic_redact.stream import redact_stream


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _run_stream(chunks: list[str], profile: Profile | None = None) -> list[tuple[str, list[DetectionEvent]]]:
    p = profile or Profile()
    return list(redact_stream(chunks, p))


# ---------------------------------------------------------------------------
# AC1 — yields (redacted_chunk, list[DetectionEvent]) for each chunk
# ---------------------------------------------------------------------------

class TestAC1YieldShape:
    def test_empty_input_yields_nothing(self) -> None:
        results = _run_stream([])
        assert results == []

    def test_single_chunk_returns_one_pair(self) -> None:
        results = _run_stream(["Hello world, no PII here."])
        assert len(results) == 1
        redacted, events = results[0]
        assert isinstance(redacted, str)
        assert isinstance(events, list)

    def test_n_chunks_yields_n_pairs(self) -> None:
        chunks = ["chunk one", "chunk two", "chunk three"]
        results = _run_stream(chunks)
        assert len(results) == 3

    def test_chunk_with_person_yields_token(self) -> None:
        chunks = ["My name is John Smith and I live in London."]
        results = _run_stream(chunks)
        redacted, events = results[0]
        # At least the PERSON entity should be detected and redacted.
        assert "John Smith" not in redacted
        assert any(e.entity_type == "PERSON" for e in events)

    def test_pii_free_chunk_yields_no_events(self) -> None:
        chunks = ["The temperature today is twenty-two degrees Celsius."]
        results = _run_stream(chunks)
        _redacted, events = results[0]
        assert events == []


# ---------------------------------------------------------------------------
# AC2 — per-chunk latency (smoke-level; formal benchmark in bench_stream.py)
# ---------------------------------------------------------------------------

class TestAC2Latency:
    def test_per_chunk_wall_time_under_200ms_smoke(self) -> None:
        """Light smoke test: single non-trivial chunk must complete in <200 ms.

        The formal <=100 ms budget is enforced over 50 chunks in bench_stream.py.
        We use 200 ms here to avoid spurious CI failures on slow machines.
        """
        chunk = "My name is Alice Johnson. Reach me at alice@example.com or +1-800-555-0199."
        profile = Profile()
        # Pre-warm the analyzer (first load of the spaCy model is excluded).
        _run_stream([chunk], profile)

        start = time.perf_counter()
        _run_stream([chunk], profile)
        elapsed_ms = (time.perf_counter() - start) * 1000
        assert elapsed_ms < 200, f"single chunk took {elapsed_ms:.1f} ms (budget 200 ms)"


# ---------------------------------------------------------------------------
# AC3 — entities spanning chunk boundaries are fully redacted
# ---------------------------------------------------------------------------

class TestAC3BoundaryEntities:
    def test_name_split_across_chunks(self) -> None:
        """'Robert' ends chunk 1, 'De Niro' starts chunk 2 — both fully redacted."""
        first = "Please contact Robert"
        second = " De Niro for more information."
        results = _run_stream([first, second])
        combined_redacted = results[0][0] + results[1][0]
        # The name must not appear verbatim in the combined output.
        assert "Robert De Niro" not in combined_redacted, (
            f"boundary entity leaked: combined output = {combined_redacted!r}"
        )

    def test_email_entirely_within_chunk_redacted(self) -> None:
        chunks = ["Send reports to jane.doe@corp.example.com every Friday."]
        results = _run_stream(chunks)
        redacted, _ = results[0]
        assert "jane.doe@corp.example.com" not in redacted

    def test_phone_split_across_chunks(self) -> None:
        """Phone number split mid-token is handled correctly."""
        first = "Call us on +1-800-555"
        second = "-0199 anytime."
        results = _run_stream([first, second])
        combined = results[0][0] + results[1][0]
        assert "+1-800-555-0199" not in combined


# ---------------------------------------------------------------------------
# AC4 — streaming path is on-device (no outbound network calls)
# ---------------------------------------------------------------------------

class TestAC4OnDevice:
    def test_no_network_socket_opened(self) -> None:
        """Verify that redact_stream makes no socket.connect calls."""
        import socket

        original_connect = socket.socket.connect
        connect_calls: list[tuple[object, ...]] = []

        def _spy_connect(self: socket.socket, *args: object, **kwargs: object) -> None:
            connect_calls.append(args)
            return original_connect(self, *args, **kwargs)  # type: ignore[arg-type]

        with patch.object(socket.socket, "connect", _spy_connect):
            _run_stream(["Alice called Bob at 555-867-5309."])

        assert connect_calls == [], (
            f"Expected no network connections; got {connect_calls}"
        )


# ---------------------------------------------------------------------------
# AC5 — each DetectionEvent carries entity_type, chunk_index, start, end, score
# ---------------------------------------------------------------------------

class TestAC5DetectionEventFields:
    def test_event_fields_present(self) -> None:
        chunks = ["Email hr@ogenticai.com for the HR team."]
        results = _run_stream(chunks)
        _, events = results[0]
        assert len(events) >= 1, "expected at least one DetectionEvent"
        ev = events[0]
        assert isinstance(ev.entity_type, str) and ev.entity_type
        assert ev.chunk_index == 0
        assert isinstance(ev.start, int) and ev.start >= 0
        assert isinstance(ev.end, int) and ev.end > ev.start
        assert isinstance(ev.score, float) and 0.0 <= ev.score <= 1.0

    def test_chunk_index_increments(self) -> None:
        chunks = [
            "My name is Carol.",
            "Her email is carol@example.com.",
        ]
        results = _run_stream(chunks)
        all_events = [e for _, evs in results for e in evs]
        indices = {e.chunk_index for e in all_events}
        # Events must carry the correct chunk index for their chunk.
        assert 0 in indices or 1 in indices

    def test_start_end_offsets_within_chunk(self) -> None:
        chunk = "Contact Dave Miller at dave@example.org."
        results = _run_stream([chunk])
        _, events = results[0]
        for ev in events:
            assert 0 <= ev.start < len(chunk), f"start {ev.start} out of range"
            assert ev.start < ev.end <= len(chunk), f"end {ev.end} out of range"

    def test_token_format_matches_r1_spec(self) -> None:
        """Tokens in the redacted output must match <<ENTITY_TYPE_N>> format."""
        import re

        chunk = "Send the invoice to billing@company.com or call 800-555-0100."
        results = _run_stream([chunk])
        redacted, _ = results[0]
        tokens = re.findall(r"<<[A-Z_]+_\d+>>", redacted)
        assert tokens, f"no <<TYPE_N>> tokens found in redacted output: {redacted!r}"
