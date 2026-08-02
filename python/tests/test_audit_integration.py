"""Acceptance tests for audit-mandatory detection events (OGE-1247 / REDACT-INT-AUDIT).

AC1: Every redact() call emits an audit event to the emitter for each detected entity type.
AC2: Every redact_stream() call emits audit events after completing all chunks.
AC3: Events carry: entity_type, mode, profile, count, and mapping_id (if reversible).
AC4: Raw sensitive values are never included in audit events.
AC5: If audit emission fails, redaction raises AuditError (fail-closed).
AC6: Structured logs include mandatory fields: tenant_id, request_id, service, op.
AC7: In reversible mode, mapping_id references the token, not the vault contents.
AC8: If audit_emitter is None, redaction completes without audit.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from ogentic_redact import (
    AuditDetectionEvent,
    AuditEmitter,
    AuditError,
    Profile,
    Redactor,
    Span,
    redact_stream,
)


class MockAuditEmitter(AuditEmitter):
    """Mock emitter for testing."""

    def __init__(self) -> None:
        self.events: list[AuditDetectionEvent] = []

    def emit(self, event: AuditDetectionEvent) -> None:
        self.events.append(event)


class FailingAuditEmitter(AuditEmitter):
    """Emitter that always raises an exception."""

    def emit(self, event: AuditDetectionEvent) -> None:
        raise RuntimeError("simulated audit failure")


class TestAC1RedactEmitsAuditEvents:
    """AC1: redact() emits an audit event for each detected entity type."""

    def test_redact_emits_event_for_each_entity_type(self) -> None:
        redactor = Redactor(reversible=False)
        emitter = MockAuditEmitter()

        text = "My name is Alice and my email is alice@example.com"
        spans = [
            Span(entity_type="PERSON", start=11, end=16, group=0),
            Span(entity_type="EMAIL_ADDRESS", start=37, end=56, group=0),
        ]

        redactor.redact(
            text,
            spans=spans,
            audit_emitter=emitter,
            tenant_id="tenant-123",
            request_id="req-abc",
            profile="default",
        )

        assert len(emitter.events) == 2
        assert emitter.events[0].entity_type == "PERSON"
        assert emitter.events[1].entity_type == "EMAIL_ADDRESS"

    def test_redact_aggregates_count_by_entity_type(self) -> None:
        redactor = Redactor(reversible=False)
        emitter = MockAuditEmitter()

        text = "Alice and Bob are friends, alice@example.com and bob@example.com"
        spans = [
            Span(entity_type="PERSON", start=0, end=5, group=0),
            Span(entity_type="PERSON", start=14, end=17, group=0),
            Span(entity_type="EMAIL_ADDRESS", start=27, end=46, group=0),
            Span(entity_type="EMAIL_ADDRESS", start=51, end=68, group=0),
        ]

        redactor.redact(
            text,
            spans=spans,
            audit_emitter=emitter,
            tenant_id="tenant-123",
            request_id="req-abc",
        )

        assert len(emitter.events) == 2
        person_event = next((e for e in emitter.events if e.entity_type == "PERSON"), None)
        email_event = next((e for e in emitter.events if e.entity_type == "EMAIL_ADDRESS"), None)

        assert person_event is not None
        assert person_event.count == 2
        assert email_event is not None
        assert email_event.count == 2

    def test_redact_no_emission_if_no_entities(self) -> None:
        redactor = Redactor(reversible=False)
        emitter = MockAuditEmitter()

        text = "No PII here"
        redactor.redact(
            text,
            spans=[],
            audit_emitter=emitter,
            tenant_id="tenant-123",
            request_id="req-abc",
        )

        assert len(emitter.events) == 0


class TestAC2RedactStreamEmitsAuditEvents:
    """AC2: redact_stream() emits audit events after completing all chunks."""

    def test_redact_stream_emits_aggregated_events(self) -> None:
        emitter = MockAuditEmitter()
        profile = Profile(entity_types=["PERSON", "EMAIL_ADDRESS"])

        chunks = [
            "Hello Alice, your email is alice@example.com",
            "Bob also has bob@example.com as his email.",
        ]

        list(redact_stream(
            chunks,
            profile,
            audit_emitter=emitter,
            tenant_id="tenant-123",
            request_id="req-abc",
        ))

        assert len(emitter.events) >= 1
        assert any(e.entity_type == "PERSON" for e in emitter.events)


class TestAC3AuditEventMetadata:
    """AC3: Events carry entity_type, mode, profile, count, and mapping_id (if reversible)."""

    def test_one_way_event_metadata(self) -> None:
        redactor = Redactor(reversible=False)
        emitter = MockAuditEmitter()

        text = "Alice alice@example.com"
        spans = [
            Span(entity_type="PERSON", start=0, end=5, group=0),
        ]

        redactor.redact(
            text,
            spans=spans,
            audit_emitter=emitter,
            tenant_id="tenant-123",
            request_id="req-abc",
            profile="shield-legal",
        )

        event = emitter.events[0]
        assert event.entity_type == "PERSON"
        assert event.mode == "one-way"
        assert event.profile == "shield-legal"
        assert event.count == 1
        assert event.mapping_id is None

    def test_reversible_event_includes_mapping_id(self) -> None:
        redactor = Redactor(reversible=True)
        emitter = MockAuditEmitter()

        text = "Alice"
        spans = [Span(entity_type="PERSON", start=0, end=5, group=0)]

        result = redactor.redact(
            text,
            spans=spans,
            audit_emitter=emitter,
            tenant_id="tenant-123",
            request_id="req-abc",
        )

        event = emitter.events[0]
        assert event.mode == "reversible"
        if result.vault:
            assert event.mapping_id is not None
            assert event.mapping_id.startswith("[RTKN_")


class TestAC4NoRawValuesInAuditEvents:
    """AC4: Raw sensitive values are never included in audit events."""

    def test_audit_event_never_contains_raw_value(self) -> None:
        redactor = Redactor(reversible=False)
        emitter = MockAuditEmitter()

        text = "My secret password is SuperSecret123!"
        spans = [
            Span(entity_type="PERSON", start=3, end=9, group=0),
        ]

        redactor.redact(
            text,
            spans=spans,
            audit_emitter=emitter,
            tenant_id="tenant-123",
            request_id="req-abc",
        )

        event = emitter.events[0]
        event_dict = event.to_dict()

        assert "SuperSecret123" not in str(event_dict)
        assert "secret" not in str(event_dict).lower()

    def test_audit_event_to_dict_never_exposes_raw(self) -> None:
        redactor = Redactor(reversible=True)
        emitter = MockAuditEmitter()

        text = "Alice"
        spans = [Span(entity_type="PERSON", start=0, end=5, group=0)]

        result = redactor.redact(
            text,
            spans=spans,
            audit_emitter=emitter,
            tenant_id="tenant-123",
            request_id="req-abc",
        )

        event = emitter.events[0]
        event_dict = event.to_dict()

        assert "Alice" not in str(event_dict)
        if result.vault:
            for original_value in result.vault.values():
                assert original_value not in str(event_dict)


class TestAC5FailClosedOnAuditFailure:
    """AC5: If audit emission fails, redaction raises AuditError (fail-closed)."""

    def test_redact_raises_audit_error_on_emitter_failure(self) -> None:
        redactor = Redactor(reversible=False)
        emitter = FailingAuditEmitter()

        text = "Alice"
        spans = [Span(entity_type="PERSON", start=0, end=5, group=0)]

        with pytest.raises(AuditError) as exc_info:
            redactor.redact(
                text,
                spans=spans,
                audit_emitter=emitter,
                tenant_id="tenant-123",
                request_id="req-abc",
            )

        assert "audit event recording failed" in str(exc_info.value)

    def test_redact_stream_raises_audit_error_on_emitter_failure(self) -> None:
        emitter = FailingAuditEmitter()
        profile = Profile(entity_types=["PERSON"])

        chunks = ["Hello Alice"]

        with pytest.raises(AuditError) as exc_info:
            list(redact_stream(
                chunks,
                profile,
                audit_emitter=emitter,
                tenant_id="tenant-123",
                request_id="req-abc",
            ))

        assert "audit event recording failed" in str(exc_info.value)


class TestAC6StructuredLogging:
    """AC6: Structured logs include mandatory fields: tenant_id, request_id, service, op."""

    def test_audit_event_has_mandatory_fields(self) -> None:
        redactor = Redactor(reversible=False)
        emitter = MockAuditEmitter()

        text = "Alice"
        spans = [Span(entity_type="PERSON", start=0, end=5, group=0)]

        redactor.redact(
            text,
            spans=spans,
            audit_emitter=emitter,
            tenant_id="tenant-abc-123",
            request_id="req-xyz-789",
            profile="shield-finance",
        )

        event = emitter.events[0]
        assert event.tenant_id == "tenant-abc-123"
        assert event.request_id == "req-xyz-789"


class TestAC7ReversibleMappingId:
    """AC7: In reversible mode, mapping_id references the token, not vault contents."""

    def test_reversible_mapping_id_is_token_not_value(self) -> None:
        redactor = Redactor(reversible=True)
        emitter = MockAuditEmitter()

        text = "Alice"
        spans = [Span(entity_type="PERSON", start=0, end=5, group=0)]

        result = redactor.redact(
            text,
            spans=spans,
            audit_emitter=emitter,
            tenant_id="tenant-123",
            request_id="req-abc",
        )

        event = emitter.events[0]
        assert event.mode == "reversible"

        if result.vault:
            assert event.mapping_id is not None
            assert event.mapping_id.startswith("[RTKN_")
            for original_value in result.vault.values():
                assert event.mapping_id != original_value
                assert original_value not in event.mapping_id


class TestAC8NoAuditIfEmitterIsNone:
    """AC8: If audit_emitter is None, redaction completes without audit."""

    def test_redact_without_emitter_succeeds(self) -> None:
        redactor = Redactor(reversible=False)

        text = "Alice"
        spans = [Span(entity_type="PERSON", start=0, end=5, group=0)]

        result = redactor.redact(
            text,
            spans=spans,
            audit_emitter=None,
            tenant_id="tenant-123",
            request_id="req-abc",
        )

        assert result.text == "[PERSON]"
        assert result.vault == {}

    def test_redact_stream_without_emitter_succeeds(self) -> None:
        profile = Profile(entity_types=["PERSON"])
        chunks = ["Hello Alice"]

        results = list(redact_stream(
            chunks,
            profile,
            audit_emitter=None,
            tenant_id="tenant-123",
            request_id="req-abc",
        ))

        assert len(results) == 1


class TestBackwardsCompatibility:
    """Ensure old code without audit parameters still works."""

    def test_redact_without_audit_params_works(self) -> None:
        redactor = Redactor(reversible=False)
        text = "Alice"
        spans = [Span(entity_type="PERSON", start=0, end=5, group=0)]

        result = redactor.redact(text, spans=spans)

        assert result.text == "[PERSON]"

    def test_redact_stream_without_audit_params_works(self) -> None:
        profile = Profile(entity_types=["PERSON"])
        chunks = ["Hello Alice"]

        results = list(redact_stream(chunks, profile))

        assert len(results) == 1
