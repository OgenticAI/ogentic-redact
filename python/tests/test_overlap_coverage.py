"""Sensitive coverage must survive label precedence and arbitrary input order."""

from __future__ import annotations

from itertools import pairwise, permutations

from hypothesis import given, settings
from hypothesis import strategies as st

from ogentic_redact import AuditEmitter, FixtureShieldAdapter, Redactor, RedactSpan, Span


def test_email_overlap_selects_longer_label_and_masks_complete_region() -> None:
    text = "alice@example.com"
    spans = [Span(0, 5, "PERSON", 3), Span(0, len(text), "EMAIL_ADDRESS", 3)]
    for order in permutations(spans):
        assert Redactor().redact(text, list(order)).text == "[EMAIL_ADDRESS]"


def test_inner_high_precedence_span_preserves_outer_sensitive_coverage() -> None:
    text = "john.smith@example.com"
    classified = [
        RedactSpan(category="EMAIL_ADDRESS", category_group="PII", start=0, end=len(text), confidence=1.0, text=text),
        RedactSpan(category="PRIVILEGE_MARKER", category_group="PRIVILEGE", start=5, end=10, confidence=1.0, text="smith"),
    ]
    for order in permutations(classified):
        redactor = Redactor(classifier=FixtureShieldAdapter(list(order)))
        assert redactor.redact(text).text == "[PRIVILEGE_MARKER]"


def test_transitive_bridge_protects_whole_union_and_keeps_adjacent_region() -> None:
    spans = [Span(0, 4, "FIRST", 0), Span(2, 8, "BRIDGE", 3), Span(6, 10, "LAST", 1), Span(10, 12, "ADJACENT", 0)]
    expected = [Span(0, 10, "FIRST", 0), Span(10, 12, "ADJACENT", 0)]
    for order in permutations(spans):
        assert Redactor.resolve_overlaps(list(order)) == expected


def test_label_ties_rank_original_start_then_length_then_category() -> None:
    cases = [
        ([Span(0, 3, "EARLY", 0), Span(1, 10, "LONGER", 0)], "EARLY"),
        ([Span(0, 3, "SHORT", 0), Span(0, 10, "LONG", 0)], "LONG"),
        ([Span(0, 10, "ZEBRA", 0), Span(0, 10, "ALPHA", 0)], "ALPHA"),
        # The outer span's start must not be reassigned to the inner label when
        # comparing it with a later member of the same connected region.
        ([Span(0, 10, "OUTER", 3), Span(5, 8, "INNER", 0), Span(3, 11, "EARLIER", 0)], "EARLIER"),
    ]
    for spans, expected in cases:
        for order in permutations(spans):
            assert Redactor.resolve_overlaps(list(order))[0].entity_type == expected


def test_reversible_union_restores_original_and_audits_regions_once() -> None:
    class Recorder(AuditEmitter):
        def __init__(self):
            self.events = []
        def emit(self, event):
            self.events.append(event)
    text = "alice@example.com and Bob"
    spans = [Span(0, 5, "PERSON", 3), Span(0, 17, "EMAIL_ADDRESS", 3), Span(22, 25, "PERSON", 3)]
    audit = Recorder()
    redactor = Redactor(reversible=True)
    result = redactor.redact(text, spans, audit_emitter=audit)
    assert redactor.unredact(result.text, result.mapping_id) == text
    mapping = redactor.mapping_store.fetch(result.mapping_id, "")
    assert set(mapping.values()) == {"alice@example.com", "Bob"}
    assert [(event.entity_type, event.count) for event in audit.events] == [("EMAIL_ADDRESS", 1), ("PERSON", 1)]


@given(st.lists(st.tuples(st.integers(0, 24), st.integers(1, 25), st.integers(0, 3)), max_size=20))
@settings(max_examples=300)
def test_union_preserves_exact_coverage_and_reversible_roundtrip(candidates) -> None:
    text = "abcdefghijklmnopqrstuvwxy"
    spans = [Span(start, end, f"TYPE_{group}", group) for start, end, group in candidates if start < end]
    resolved = Redactor.resolve_overlaps(spans)
    covered = {i for span in spans for i in range(span.start, span.end)}
    protected = {i for span in resolved for i in range(span.start, span.end)}
    assert protected == covered
    assert all(left.end <= right.start for left, right in pairwise(resolved))
    assert resolved == Redactor.resolve_overlaps(list(reversed(spans)))
    redactor = Redactor(reversible=True)
    result = redactor.redact(text, spans)
    assert redactor.unredact(result.text, result.mapping_id) == text
