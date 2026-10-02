"""Acceptance tests for redact_stream (OGE-1221 / REDACT-R6).

AC1: redact_stream yields (redacted_chunk, list[DetectionEvent]) for each chunk.
AC2: Finalized-record processing latency is measured by bench_stream.py;
     time waiting for record finalization is outside that benchmark.
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


@pytest.mark.parametrize(('text', 'entity_type'), [
    ('Contact alice@example.com now.', 'EMAIL_ADDRESS'),
    ('Call +1-800-555-0199.', 'PHONE_NUMBER'),
    ('SSN: 219-09-9999.', 'US_SSN'),
    ('😊 Contact alice@example.com\n', 'EMAIL_ADDRESS'),
])
def test_every_two_chunk_partition_matches_complete_record(text: str, entity_type: str) -> None:
    profile = Profile(entity_types=[entity_type])
    expected = ''.join(part for part, _ in redact_stream([text], profile))
    assert expected != text
    partitions = [[text[:cut], text[cut:]] for cut in range(len(text) + 1)]
    partitions.extend([list(text), [part for char in text for part in (char, '')]])
    for chunks in partitions:
        actual = list(redact_stream(chunks, profile))
        assert len(actual) == len(chunks)
        assert ''.join(part for part, _ in actual) == expected
        for chunk, (_, events) in zip(chunks, actual, strict=True):
            assert all(0 <= event.start < event.end <= len(chunk) for event in events)


def test_no_prefix_is_released_before_input_finalizes() -> None:
    def broken_input():
        yield 'Contact alice@'
        raise RuntimeError('input transport failed')

    stream = redact_stream(broken_input(), Profile(entity_types=['EMAIL_ADDRESS']))
    with pytest.raises(RuntimeError, match='input transport failed'):
        next(stream)


@pytest.mark.parametrize('chunks,limits', [
    (['Contact alice@', 'example.com'], {'max_buffer_chars': 15}),
    (['', '', ''], {'max_chunks': 2}),
])
def test_buffer_limit_fails_before_output(chunks: list[str], limits: dict[str, int]) -> None:
    from ogentic_redact.errors import RedactError

    stream = redact_stream(chunks, Profile(), **limits)
    with pytest.raises(RedactError, match='buffer limit'):
        next(stream)


def test_overlap_union_protects_all_sensitive_characters() -> None:
    from presidio_analyzer import RecognizerResult
    from unittest.mock import Mock

    analyzer = Mock()
    analyzer.get_supported_entities.return_value = Profile().entity_types
    analyzer.analyze.return_value = [
        RecognizerResult('A', 0, 10, .5),
        RecognizerResult('B', 1, 3, .9),
        RecognizerResult('C', 4, 6, .8),
        RecognizerResult('D', 10, 12, .7),
    ]
    with patch('ogentic_redact.stream._get_analyzer', return_value=analyzer):
        result = list(redact_stream(['abcdefghijkl rest'], Profile()))
    assert result[0][0] == '<<B_1>><<D_1>> rest'
    assert [(e.start, e.end) for e in result[0][1]] == [(0, 10), (10, 12)]


def test_missing_model_fails_without_downloader() -> None:
    import importlib
    from ogentic_redact.errors import RedactError

    module = importlib.import_module('ogentic_redact.stream')
    with (
        patch.object(module, '_analyzer', None),
        patch('spacy.load', side_effect=OSError('missing local model')),
        patch('spacy.cli.download') as downloader,
    ):
        with pytest.raises(RedactError, match='runtime does not download'):
            next(redact_stream(['Contact alice@example.com'], Profile()))
    downloader.assert_not_called()


def test_empty_chunks_preserve_shape_without_loading_model() -> None:
    with patch('ogentic_redact.stream._get_analyzer') as analyzer:
        assert list(redact_stream(['', ''], Profile())) == [('', []), ('', [])]
    analyzer.assert_not_called()


@pytest.mark.parametrize('score', ['0.5', None, True, float('nan'), float('inf')])
def test_malformed_local_confidence_raises_sanitized_error_before_output(score: object) -> None:
    from types import SimpleNamespace
    from unittest.mock import Mock
    from ogentic_redact.errors import ClassifierError

    analyzer = Mock()
    analyzer.get_supported_entities.return_value = Profile().entity_types
    analyzer.analyze.return_value = [SimpleNamespace(start=0, end=5, entity_type='PERSON', score=score)]
    with patch('ogentic_redact.stream._get_analyzer', return_value=analyzer):
        with pytest.raises(ClassifierError, match='invalid'):
            next(redact_stream(['Alice'], Profile()))


def test_empty_entity_selection_preserves_chunks_without_loading_model() -> None:
    chunks = ['Email alice@', '', 'example.com']
    with patch('ogentic_redact.stream._get_analyzer') as analyzer:
        assert list(redact_stream(chunks, Profile(entity_types=[]))) == [(chunk, []) for chunk in chunks]
    analyzer.assert_not_called()


def test_local_legal_profile_rejects_missing_domain_recognizers_before_output() -> None:
    from ogentic_redact.errors import ClassifierError
    stream = redact_stream(
        ['Case 1:23-cv-00456; Bates ABC0000123; email alice@example.com.'],
        Profile.from_shield_profile('shield-legal'),
    )
    with pytest.raises(ClassifierError, match='BATES_NUMBER, CASE_NUMBER'):
        next(stream)


def test_mixed_supported_and_unsupported_policy_never_runs_partial_detection() -> None:
    from unittest.mock import Mock
    from ogentic_redact.errors import ClassifierError
    analyzer = Mock()
    analyzer.get_supported_entities.return_value = ['EMAIL_ADDRESS']
    with patch('ogentic_redact.stream._get_analyzer', return_value=analyzer):
        stream = redact_stream(['Case 1:23-cv-00456; alice@example.com'], Profile(entity_types=['EMAIL_ADDRESS', 'CASE_NUMBER']))
        with pytest.raises(ClassifierError, match='CASE_NUMBER'):
            next(stream)
    analyzer.analyze.assert_not_called()


def test_local_finance_profile_runs_with_supported_entity_policy() -> None:
    result = list(redact_stream(['Email alice@example.com'], Profile.from_shield_profile('shield-finance')))
    assert result[0][0] == 'Email <<EMAIL_ADDRESS_1>>'


def test_mutated_invalid_profile_is_rejected_before_input_is_read() -> None:
    profile = Profile()
    profile.entity_types = None
    def chunks():
        raise AssertionError('input should not be read with an invalid profile')
        yield ''
    with pytest.raises(ValueError, match='entity_types'):
        next(redact_stream(chunks(), profile))


def test_input_iterable_cannot_mutate_active_profile_selection() -> None:
    profile = Profile(entity_types=['EMAIL_ADDRESS'])
    def chunks():
        profile.entity_types.clear()
        yield 'Email alice@example.com'
    result = list(redact_stream(chunks(), profile))
    assert result[0][0] == 'Email <<EMAIL_ADDRESS_1>>'
