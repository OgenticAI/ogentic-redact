"""OGE-1274 — Property + determinism tests for round-trip and salt invariants.

Covers all five acceptance criteria:
  AC-1  Round-trip identity holds for generated inputs.
  AC-2  No two calls produce identical tokens for the same value (default salt).
  AC-3  Within-call token stability.
  AC-4  Overlap resolver always returns the precedence winner.
  AC-5  At least one failure-path test per public API method.
"""

from __future__ import annotations

import pytest
from hypothesis import assume, given, settings
from hypothesis import strategies as st

from ogentic_redact.redactor import Redactor
from ogentic_redact.span import Span

# ---------------------------------------------------------------------------
# Shared strategies
# ---------------------------------------------------------------------------

# Restrict to printable ASCII letters, digits, and spaces so the generated
# text never accidentally contains the token prefix "[RTKN_", which would
# interfere with vault substitution during unredact.
_SAFE_ALPHA = st.characters(whitelist_categories=("Lu", "Ll", "Nd", "Zs"))
_SAFE_TEXT = st.text(alphabet=_SAFE_ALPHA, min_size=0, max_size=200)
_NONEMPTY_TEXT = _SAFE_TEXT.filter(lambda t: len(t) >= 1)
_ENTITY_TYPES = st.sampled_from(["EMAIL", "PHONE", "NAME", "SSN", "DATE"])


# ---------------------------------------------------------------------------
# AC-1: Round-trip identity holds for generated inputs
# ---------------------------------------------------------------------------


@given(text=_SAFE_TEXT)
@settings(max_examples=300)
def test_round_trip_identity_empty_spans(text: str) -> None:
    """unredact(redact(x, []).text, vault) == x for any text with no spans."""
    r = Redactor(reversible=True)
    result = r.redact(text, [])
    assert r.unredact(result.text, result.vault) == text


@given(
    text=_SAFE_TEXT.filter(lambda t: len(t) >= 2),
    entity_type=_ENTITY_TYPES,
)
@settings(max_examples=300)
def test_round_trip_identity_single_span(text: str, entity_type: str) -> None:
    """Round-trip identity holds when a span covers part of the text."""
    r = Redactor(reversible=True)
    end = max(1, len(text) // 2)
    span = Span(start=0, end=end, entity_type=entity_type, group=0)
    result = r.redact(text, [span])
    assert r.unredact(result.text, result.vault) == text


@given(
    text=_SAFE_TEXT.filter(lambda t: len(t) >= 1),
    entity_type=_ENTITY_TYPES,
)
@settings(max_examples=300)
def test_round_trip_identity_full_span(text: str, entity_type: str) -> None:
    """Round-trip identity holds when the span covers the entire text."""
    r = Redactor(reversible=True)
    span = Span(start=0, end=len(text), entity_type=entity_type, group=0)
    result = r.redact(text, [span])
    assert r.unredact(result.text, result.vault) == text


# ---------------------------------------------------------------------------
# AC-2: No two calls produce identical tokens for the same value
# ---------------------------------------------------------------------------


@given(text=_NONEMPTY_TEXT, entity_type=_ENTITY_TYPES)
@settings(max_examples=300)
def test_tokens_differ_across_calls(text: str, entity_type: str) -> None:
    """Per-call salt makes token sets from independent calls disjoint."""
    span = Span(start=0, end=len(text), entity_type=entity_type, group=0)
    r = Redactor(reversible=True)
    result_a = r.redact(text, [span])
    result_b = r.redact(text, [span])
    assert set(result_a.vault.keys()).isdisjoint(set(result_b.vault.keys()))


@given(text=_NONEMPTY_TEXT, entity_type=_ENTITY_TYPES)
@settings(max_examples=100)
def test_tokens_differ_across_three_calls(text: str, entity_type: str) -> None:
    """Token sets across three independent calls are mutually disjoint."""
    span = Span(start=0, end=len(text), entity_type=entity_type, group=0)
    r = Redactor(reversible=True)
    sets = [set(r.redact(text, [span]).vault.keys()) for _ in range(3)]
    # Each pair must be disjoint
    assert sets[0].isdisjoint(sets[1])
    assert sets[0].isdisjoint(sets[2])
    assert sets[1].isdisjoint(sets[2])


# ---------------------------------------------------------------------------
# AC-3: Within-call token stability
# ---------------------------------------------------------------------------


@given(
    value=_NONEMPTY_TEXT,
    sep=st.text(
        alphabet=st.characters(whitelist_categories=("Zs",)),
        min_size=1,
        max_size=4,
    ),
    entity_type=_ENTITY_TYPES,
)
@settings(max_examples=300)
def test_within_call_token_stability(value: str, sep: str, entity_type: str) -> None:
    """Same value in the same call receives the same token (within-call stability)."""
    text = value + sep + value
    span1 = Span(start=0, end=len(value), entity_type=entity_type, group=0)
    span2 = Span(
        start=len(value) + len(sep),
        end=len(text),
        entity_type=entity_type,
        group=0,
    )
    r = Redactor(reversible=True)
    result = r.redact(text, [span1, span2])
    # Same value and entity_type → one unique vault entry
    assert len(result.vault) == 1
    (token,) = result.vault.keys()
    # Token appears twice in the redacted text
    assert result.text.count(token) == 2


@given(
    value=_NONEMPTY_TEXT,
    entity_type=_ENTITY_TYPES,
)
@settings(max_examples=200)
def test_within_call_vault_maps_to_original(value: str, entity_type: str) -> None:
    """The vault entry maps back to the original span value."""
    span = Span(start=0, end=len(value), entity_type=entity_type, group=0)
    r = Redactor(reversible=True)
    result = r.redact(value, [span])
    assert len(result.vault) == 1
    assert next(iter(result.vault.values())) == value


# ---------------------------------------------------------------------------
# AC-4: Overlap resolver always returns the precedence winner
# ---------------------------------------------------------------------------


@given(
    start=st.integers(min_value=0, max_value=50),
    length=st.integers(min_value=2, max_value=20),
    overlap=st.integers(min_value=1, max_value=10),
)
@settings(max_examples=300)
def test_overlap_resolver_high_beats_low_precedence(
    start: int, length: int, overlap: int
) -> None:
    """Lower group number (higher precedence) span wins when spans overlap."""
    # Spans overlap only when overlap < length (otherwise they're adjacent).
    assume(overlap < length)
    span_hi = Span(start=start, end=start + length, entity_type="HI", group=0)
    span_lo = Span(
        start=start + overlap,
        end=start + overlap + length,
        entity_type="LO",
        group=1,
    )
    result = Redactor.resolve_overlaps([span_hi, span_lo])
    assert result == [span_hi]


@given(
    start=st.integers(min_value=0, max_value=50),
    length=st.integers(min_value=2, max_value=20),
    overlap=st.integers(min_value=1, max_value=10),
)
@settings(max_examples=300)
def test_overlap_resolver_order_invariant(
    start: int, length: int, overlap: int
) -> None:
    """Overlap resolution is independent of input ordering."""
    assume(overlap < length)
    span_hi = Span(start=start, end=start + length, entity_type="HI", group=0)
    span_lo = Span(
        start=start + overlap,
        end=start + overlap + length,
        entity_type="LO",
        group=1,
    )
    assert Redactor.resolve_overlaps([span_hi, span_lo]) == Redactor.resolve_overlaps(
        [span_lo, span_hi]
    )


@given(
    a_start=st.integers(min_value=0, max_value=40),
    a_len=st.integers(min_value=1, max_value=10),
    gap=st.integers(min_value=1, max_value=10),
    b_len=st.integers(min_value=1, max_value=10),
)
@settings(max_examples=300)
def test_non_overlapping_spans_all_preserved(
    a_start: int, a_len: int, gap: int, b_len: int
) -> None:
    """Non-overlapping spans are all kept by the resolver."""
    a_end = a_start + a_len
    b_start = a_end + gap
    b_end = b_start + b_len
    span_a = Span(start=a_start, end=a_end, entity_type="A", group=0)
    span_b = Span(start=b_start, end=b_end, entity_type="B", group=0)
    result = Redactor.resolve_overlaps([span_a, span_b])
    assert len(result) == 2
    assert span_a in result
    assert span_b in result


@given(
    start=st.integers(min_value=0, max_value=50),
    length=st.integers(min_value=2, max_value=20),
    overlap=st.integers(min_value=1, max_value=10),
)
@settings(max_examples=300)
def test_overlap_resolver_output_is_sorted(
    start: int, length: int, overlap: int
) -> None:
    """resolve_overlaps always returns spans in start-ascending order."""
    span_a = Span(start=start, end=start + length, entity_type="A", group=0)
    span_b = Span(
        start=start + overlap + length,
        end=start + overlap + length * 2,
        entity_type="B",
        group=0,
    )
    result = Redactor.resolve_overlaps([span_b, span_a])
    starts = [s.start for s in result]
    assert starts == sorted(starts)


# ---------------------------------------------------------------------------
# AC-5: Failure-path coverage per public API method
# ---------------------------------------------------------------------------


# --- Redactor.redact failure paths ---


def test_redact_raises_on_end_exceeds_text() -> None:
    """`redact()` raises ValueError when span.end > len(text)."""
    r = Redactor()
    with pytest.raises(ValueError, match="Invalid span"):
        r.redact("hi", [Span(start=0, end=100, entity_type="X", group=0)])


def test_redact_raises_on_start_equals_end() -> None:
    """`redact()` raises ValueError when span.start == span.end (zero-length)."""
    r = Redactor()
    with pytest.raises(ValueError, match="Invalid span"):
        r.redact("hello", [Span(start=2, end=2, entity_type="X", group=0)])


def test_redact_raises_on_inverted_span() -> None:
    """`redact()` raises ValueError when span.start > span.end."""
    r = Redactor()
    with pytest.raises(ValueError, match="Invalid span"):
        r.redact("hello", [Span(start=4, end=2, entity_type="X", group=0)])


def test_redact_raises_on_negative_start() -> None:
    """`redact()` raises ValueError when span.start < 0."""
    r = Redactor()
    with pytest.raises(ValueError, match="Invalid span"):
        r.redact("hello", [Span(start=-1, end=3, entity_type="X", group=0)])


def test_redact_raises_on_non_string_text() -> None:
    """`redact()` raises TypeError when text is not a str."""
    r = Redactor()
    with pytest.raises(TypeError):
        r.redact(42, [])  # type: ignore[arg-type]


# --- Redactor.unredact failure paths ---


def test_unredact_raises_when_not_reversible() -> None:
    """`unredact()` raises ValueError on a one-way Redactor."""
    r = Redactor(reversible=False)
    with pytest.raises(ValueError, match="reversible"):
        r.unredact("text", {})


def test_unredact_raises_on_missing_token() -> None:
    """`unredact()` raises KeyError when a vault token is not in the text."""
    r = Redactor(reversible=True)
    with pytest.raises(KeyError):
        r.unredact("no tokens here", {"[RTKN_deadbeef0000]": "secret"})


def test_unredact_raises_on_non_string_input() -> None:
    """`unredact()` raises TypeError when redacted_text is not a str."""
    r = Redactor(reversible=True)
    with pytest.raises(TypeError):
        r.unredact(None, {})  # type: ignore[arg-type]


def test_unredact_empty_vault_returns_text_unchanged() -> None:
    """`unredact()` with an empty vault returns the text unchanged."""
    r = Redactor(reversible=True)
    assert r.unredact("some text", {}) == "some text"


# --- Redactor.resolve_overlaps failure paths ---


def test_resolve_overlaps_empty_list() -> None:
    """`resolve_overlaps([])` returns an empty list (no error)."""
    assert Redactor.resolve_overlaps([]) == []


def test_resolve_overlaps_single_span_returned_unchanged() -> None:
    """`resolve_overlaps` with one span returns it in a list."""
    span = Span(start=5, end=10, entity_type="X", group=0)
    assert Redactor.resolve_overlaps([span]) == [span]


def test_resolve_overlaps_identical_spans_keeps_one() -> None:
    """Duplicate spans collapse to one."""
    span = Span(start=0, end=5, entity_type="X", group=0)
    result = Redactor.resolve_overlaps([span, span])
    assert len(result) == 1
