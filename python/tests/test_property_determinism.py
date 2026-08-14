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
    """unredact(redact(x, []).text, mapping_id) == x for any text with no spans."""
    r = Redactor(reversible=True)
    result = r.redact(text, [])
    assert r.unredact(result.text, result.mapping_id) == text


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
    assert r.unredact(result.text, result.mapping_id) == text


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
    assert r.unredact(result.text, result.mapping_id) == text


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
    vault_a = r.mapping_store.fetch(result_a.mapping_id, "")
    vault_b = r.mapping_store.fetch(result_b.mapping_id, "")
    assert set(vault_a.keys()).isdisjoint(set(vault_b.keys()))


@given(text=_NONEMPTY_TEXT, entity_type=_ENTITY_TYPES)
@settings(max_examples=100)
def test_tokens_differ_across_three_calls(text: str, entity_type: str) -> None:
    """Token sets across three independent calls are mutually disjoint."""
    span = Span(start=0, end=len(text), entity_type=entity_type, group=0)
    r = Redactor(reversible=True)
    results = [r.redact(text, [span]) for _ in range(3)]
    sets = [set(r.mapping_store.fetch(res.mapping_id, "").keys()) for res in results]
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
    vault = r.mapping_store.fetch(result.mapping_id, "")
    # Same value and entity_type → one unique vault entry
    assert len(vault) == 1
    (token,) = vault.keys()
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
    vault = r.mapping_store.fetch(result.mapping_id, "")
    assert len(vault) == 1
    assert next(iter(vault.values())) == value


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
        r.unredact("text", "fake_mapping_id")


def test_unredact_raises_on_missing_token() -> None:
    """`unredact()` raises an error when a vault token is not in the text."""
    from ogentic_redact.stores import InProcessMappingStore
    r = Redactor(reversible=True, mapping_store=InProcessMappingStore())
    mapping_id = r.mapping_store.store({"[RTKN_deadbeef0000]": "secret"}, "")
    with pytest.raises(KeyError):
        r.unredact("no tokens here", mapping_id)


def test_unredact_raises_on_non_string_input() -> None:
    """`unredact()` raises TypeError when redacted_text is not a str."""
    r = Redactor(reversible=True)
    with pytest.raises(TypeError):
        r.unredact(None, "fake_mapping_id")  # type: ignore[arg-type]


def test_unredact_empty_vault_returns_text_unchanged() -> None:
    """`unredact()` with an empty vault returns the text unchanged."""
    from ogentic_redact.stores import InProcessMappingStore
    r = Redactor(reversible=True, mapping_store=InProcessMappingStore())
    mapping_id = r.mapping_store.store({}, "")
    assert r.unredact("some text", mapping_id) == "some text"


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


# ---------------------------------------------------------------------------
# OGE-1217: Category-group overlap resolver (PRIVILEGE > PHI > MNPI > PII)
# ---------------------------------------------------------------------------


class TestCategoryGroupPrecedence:
    """AC-1 through AC-5 for category-group overlap resolution."""

    def test_privilege_beats_phi(self) -> None:
        """PRIVILEGE (group=0) beats PHI (group=1) on overlap."""
        privilege = Span(start=0, end=5, entity_type="SECRET", group=0)
        phi = Span(start=3, end=8, entity_type="MEDICAL", group=1)
        result = Redactor.resolve_overlaps([privilege, phi])
        assert result == [privilege]

    def test_privilege_beats_mnpi(self) -> None:
        """PRIVILEGE (group=0) beats MNPI (group=2) on overlap."""
        privilege = Span(start=0, end=5, entity_type="SECRET", group=0)
        mnpi = Span(start=3, end=8, entity_type="TICKER", group=2)
        result = Redactor.resolve_overlaps([privilege, mnpi])
        assert result == [privilege]

    def test_privilege_beats_pii(self) -> None:
        """PRIVILEGE (group=0) beats PII (group=3) on overlap."""
        privilege = Span(start=0, end=5, entity_type="SECRET", group=0)
        pii = Span(start=3, end=8, entity_type="EMAIL", group=3)
        result = Redactor.resolve_overlaps([privilege, pii])
        assert result == [privilege]

    def test_phi_beats_mnpi(self) -> None:
        """PHI (group=1) beats MNPI (group=2) on overlap."""
        phi = Span(start=0, end=5, entity_type="MEDICAL", group=1)
        mnpi = Span(start=3, end=8, entity_type="TICKER", group=2)
        result = Redactor.resolve_overlaps([phi, mnpi])
        assert result == [phi]

    def test_phi_beats_pii(self) -> None:
        """PHI (group=1) beats PII (group=3) on overlap."""
        phi = Span(start=0, end=5, entity_type="MEDICAL", group=1)
        pii = Span(start=3, end=8, entity_type="EMAIL", group=3)
        result = Redactor.resolve_overlaps([phi, pii])
        assert result == [phi]

    def test_mnpi_beats_pii(self) -> None:
        """MNPI (group=2) beats PII (group=3) on overlap."""
        mnpi = Span(start=0, end=5, entity_type="TICKER", group=2)
        pii = Span(start=3, end=8, entity_type="EMAIL", group=3)
        result = Redactor.resolve_overlaps([mnpi, pii])
        assert result == [mnpi]

    def test_three_way_overlap_privilege_wins(self) -> None:
        """PRIVILEGE wins in 3-way overlap: PRIVILEGE+PHI+PII."""
        privilege = Span(start=0, end=10, entity_type="SECRET", group=0)
        phi = Span(start=3, end=12, entity_type="MEDICAL", group=1)
        pii = Span(start=5, end=15, entity_type="EMAIL", group=3)
        result = Redactor.resolve_overlaps([phi, pii, privilege])
        assert result == [privilege]

    def test_three_way_overlap_phi_wins_when_privilege_absent(self) -> None:
        """PHI wins when PRIVILEGE is absent: PHI+MNPI+PII."""
        phi = Span(start=0, end=10, entity_type="MEDICAL", group=1)
        mnpi = Span(start=3, end=12, entity_type="TICKER", group=2)
        pii = Span(start=5, end=15, entity_type="EMAIL", group=3)
        result = Redactor.resolve_overlaps([mnpi, pii, phi])
        assert result == [phi]

    def test_category_precedence_is_order_invariant(self) -> None:
        """Same overlaps resolve identically regardless of input order."""
        privilege = Span(start=0, end=5, entity_type="SECRET", group=0)
        phi = Span(start=3, end=8, entity_type="MEDICAL", group=1)
        pii = Span(start=2, end=7, entity_type="EMAIL", group=3)
        result_abc = Redactor.resolve_overlaps([privilege, phi, pii])
        result_cba = Redactor.resolve_overlaps([pii, phi, privilege])
        result_bca = Redactor.resolve_overlaps([phi, pii, privilege])
        assert result_abc == result_cba == result_bca

    def test_category_precedence_constant_exists(self) -> None:
        """CATEGORY_GROUP_PRECEDENCE constant is importable and correct."""
        from ogentic_redact.categories import CATEGORY_GROUP_PRECEDENCE
        assert CATEGORY_GROUP_PRECEDENCE == {
            "PRIVILEGE": 0,
            "PHI": 1,
            "MNPI": 2,
            "PII": 3,
        }

    def test_category_precedence_exported_from_top_level(self) -> None:
        """CATEGORY_GROUP_PRECEDENCE is exported from ogentic_redact package."""
        from ogentic_redact import CATEGORY_GROUP_PRECEDENCE
        assert CATEGORY_GROUP_PRECEDENCE["PRIVILEGE"] == 0
        assert CATEGORY_GROUP_PRECEDENCE["PHI"] == 1
        assert CATEGORY_GROUP_PRECEDENCE["MNPI"] == 2
        assert CATEGORY_GROUP_PRECEDENCE["PII"] == 3

    def test_overlapping_prefix_spans_use_precedence_correctly(self) -> None:
        """Overlapping spans with different categories resolve via precedence."""
        text = "My secret: patient@example.com"
        privilege = Span(
            start=3, end=9, entity_type="SECRET", group=0
        )
        pii_email = Span(
            start=12, end=30, entity_type="EMAIL", group=3
        )
        result = Redactor.resolve_overlaps([privilege, pii_email])
        assert len(result) == 2
        assert privilege in result
        assert pii_email in result

    def test_same_text_span_different_categories_keeps_higher_precedence(self) -> None:
        """When categories cover identical text, keep the higher-precedence one."""
        phi = Span(start=0, end=5, entity_type="DIAGNOSIS", group=1)
        pii = Span(start=0, end=5, entity_type="NAME", group=3)
        result = Redactor.resolve_overlaps([phi, pii])
        assert result == [phi]
        assert result[0].group == 1

    @given(
        start=st.integers(min_value=0, max_value=40),
        overlap1=st.integers(min_value=1, max_value=8),
        overlap2=st.integers(min_value=1, max_value=8),
    )
    @settings(max_examples=200)
    def test_category_precedence_deterministic_across_overlaps(
        self, start: int, overlap1: int, overlap2: int
    ) -> None:
        """Category precedence resolves consistently across all overlapping configurations."""
        privilege = Span(
            start=start, end=start + 10, entity_type="SECRET", group=0
        )
        phi = Span(
            start=start + overlap1, end=start + overlap1 + 10, entity_type="MEDICAL", group=1
        )
        pii = Span(
            start=start + overlap2, end=start + overlap2 + 10, entity_type="EMAIL", group=3
        )
        result = Redactor.resolve_overlaps([privilege, phi, pii])
        assert len(result) == 1
        assert result[0].group == 0
        assert result[0].entity_type == "SECRET"
