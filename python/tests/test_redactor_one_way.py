"""Acceptance tests for one-way mode, localhost-only guard, and cloud opt-in."""

from __future__ import annotations

import warnings

import pytest

from ogentic_redact import LocalhostOnlyError
from ogentic_redact.redactor import Redactor, _cloud_warned
from ogentic_redact.span import Span


class TestOneWayIrreversible:
    """One-way mode is irreversible by construction."""

    def test_one_way_no_vault(self) -> None:
        redactor = Redactor(reversible=False)
        text = "My email is alice@example.com"
        result = redactor.redact(
            text,
            [Span(start=12, end=29, entity_type="EMAIL_ADDRESS", group=0)],
        )
        assert result.vault == {}
        assert "[EMAIL_ADDRESS]" in result.text
        assert "alice@example.com" not in result.text

    def test_one_way_simple_placeholder(self) -> None:
        redactor = Redactor(reversible=False)
        result = redactor.redact(
            "John Smith works here",
            [Span(start=0, end=10, entity_type="PERSON", group=0)],
        )
        assert result.text == "[PERSON] works here"
        assert result.vault == {}

    def test_reversible_has_vault(self) -> None:
        redactor = Redactor(reversible=True)
        text = "My email is alice@example.com"
        result = redactor.redact(
            text,
            [Span(start=12, end=29, entity_type="EMAIL_ADDRESS", group=0)],
        )
        # Reversible mode stores the mapping in the Vault (never inline), and
        # returns an opaque mapping_id; RedactResult.vault stays empty.
        assert result.mapping_id is not None
        assert result.vault == {}
        mapping = redactor.vault.fetch(result.mapping_id, "")
        assert any("alice@example.com" in v for v in mapping.values())


class TestLocalhostOnlyGuard:
    """Default path raises guard error on cloud attempts (future stub)."""

    def test_localhost_only_default(self) -> None:
        redactor = Redactor(cloud=False)
        text = "Contact: alice@example.com"
        result = redactor.redact(
            text,
            [Span(start=9, end=26, entity_type="EMAIL_ADDRESS", group=0)],
        )
        assert "[EMAIL_ADDRESS]" in result.text
        assert "alice@example.com" not in result.text


class TestCloudOptIn:
    """Cloud opt-in emits first-use warning only."""

    def test_cloud_opt_in_warning(self) -> None:
        import ogentic_redact.redactor as redactor_module
        redactor_module._cloud_warned = False

        redactor = Redactor(cloud=True)
        text = "Contact: alice@example.com"
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            redactor.redact(
                text,
                [Span(start=9, end=26, entity_type="EMAIL_ADDRESS", group=0)],
            )
            assert len(w) == 1
            assert issubclass(w[0].category, UserWarning)
            assert "Cloud-assisted recognisers are enabled" in str(w[0].message)

    def test_cloud_opt_in_warning_once_per_process(self) -> None:
        import ogentic_redact.redactor as redactor_module
        redactor_module._cloud_warned = False

        redactor1 = Redactor(cloud=True)
        redactor2 = Redactor(cloud=True)

        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            redactor1.redact(
                "Test 1",
                [Span(start=0, end=1, entity_type="PERSON", group=0)],
            )
            redactor2.redact(
                "Test 2",
                [Span(start=0, end=1, entity_type="PERSON", group=0)],
            )
            warning_count = len([x for x in w if issubclass(x.category, UserWarning)])
            assert warning_count == 1

    def test_cloud_false_no_warning(self) -> None:
        import ogentic_redact.redactor as redactor_module
        redactor_module._cloud_warned = False

        redactor = Redactor(cloud=False)
        text = "Contact: alice@example.com"
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            redactor.redact(
                text,
                [Span(start=9, end=26, entity_type="EMAIL_ADDRESS", group=0)],
            )
            warning_count = len(
                [x for x in w if "Cloud-assisted" in str(x.message)]
            )
            assert warning_count == 0


class TestF3VectorCompliance:
    """One-way output is irreversible and satisfies F3 (no reidentification risk)."""

    def test_one_way_no_reidentification_path(self) -> None:
        redactor = Redactor(reversible=False)
        text = "John Doe, john@example.com, SSN: 123-45-6789"
        redacted = redactor.redact(
            text,
            [
                Span(start=0, end=8, entity_type="PERSON", group=0),
                Span(start=11, end=27, entity_type="EMAIL_ADDRESS", group=0),
                Span(start=35, end=44, entity_type="US_SSN", group=0),
            ],
        )
        assert redacted.vault == {}
        assert "John Doe" not in redacted.text
        assert "john@example.com" not in redacted.text
        assert "123-45-6789" not in redacted.text
        assert "[PERSON]" in redacted.text
        assert "[EMAIL_ADDRESS]" in redacted.text
        assert "[US_SSN]" in redacted.text


class TestFailurePathCloudRejection:
    """Stub: Future cloud recogniser without opt-in raises LocalhostOnlyError."""

    def test_cloud_error_exported(self) -> None:
        assert LocalhostOnlyError is not None
        error = LocalhostOnlyError()
        assert "Cloud recognisers require explicit opt-in" in str(error)
        assert "cloud=True" in str(error)
        assert "on-device only" in str(error)
