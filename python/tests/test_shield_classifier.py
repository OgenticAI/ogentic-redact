"""Acceptance tests for the Shield classifier boundary (OGE-1230).

Covers the five ACs: classifier DI into the core (AC1), the RedactSpan model and
its mapping from Shield's shape (AC2), Shield profile constants (AC3), the
Protocol boundary isolating the HTTP adapter (AC4), and the fixture-driven
end-to-end flow with no HTTP (AC5).
"""

from __future__ import annotations

from typing import Any

import pytest

from ogentic_redact import (
    KNOWN_PROFILES,
    SHIELD_FINANCE,
    SHIELD_LEGAL,
    SHIELD_PROFILES,
    ClassifierError,
    ClassifierProtocol,
    FixtureShieldAdapter,
    Redactor,
    RedactSpan,
    ShieldAdapter,
    Span,
)

TEXT = "Email alice@example.com, SSN 123-45-6789."
# Offsets into TEXT.
EMAIL = RedactSpan(category="EMAIL_ADDRESS", start=6, end=23, confidence=0.98, text="alice@example.com")
SSN = RedactSpan(category="US_SSN", start=29, end=40, confidence=0.95, text="123-45-6789")


# ── AC2: the RedactSpan model + mapping from Shield's response shape ───────────
class TestRedactSpan:
    def test_from_shield_entity_maps_fields(self) -> None:
        entity = {
            "text": "alice@example.com",
            "category": "EMAIL_ADDRESS",
            "category_group": "PII",  # extra Shield fields are ignored
            "confidence": 0.97,
            "detection_layer": "pattern",
            "start": 6,
            "end": 23,
        }
        span = RedactSpan.from_shield_entity(entity)
        assert (span.category, span.start, span.end, span.text) == (
            "EMAIL_ADDRESS",
            6,
            23,
            "alice@example.com",
        )
        assert span.confidence == pytest.approx(0.97)

    def test_confidence_defaults_to_one_when_absent(self) -> None:
        span = RedactSpan.from_shield_entity({"category": "PERSON", "start": 0, "end": 4})
        assert span.confidence == 1.0

    def test_malformed_entity_raises_classifier_error(self) -> None:
        with pytest.raises(ClassifierError):
            RedactSpan.from_shield_entity({"category": "PERSON"})  # missing start/end

    def test_invalid_confidence_rejected(self) -> None:
        with pytest.raises(ValueError):
            RedactSpan(category="X", start=0, end=1, confidence=1.5, text="")

    def test_to_span_precedence_from_category_group(self) -> None:
        # PHI outranks (lower group than) PII; unknown categories fall to lowest.
        assert RedactSpan(category="PHI", start=0, end=1, confidence=1.0).to_span().group == 1
        assert RedactSpan(category="PII", start=0, end=1, confidence=1.0).to_span().group == 3
        unknown = RedactSpan(category="EMAIL_ADDRESS", start=0, end=1, confidence=1.0).to_span()
        assert unknown.group == 4  # len(CATEGORY_GROUP_PRECEDENCE)
        assert isinstance(unknown, Span)


# ── AC3: Shield profile taxonomy as first-class constants ─────────────────────
class TestProfiles:
    def test_constants(self) -> None:
        assert SHIELD_LEGAL == "shield-legal"
        assert SHIELD_FINANCE == "shield-finance"
        assert SHIELD_PROFILES == frozenset({SHIELD_LEGAL, SHIELD_FINANCE})

    def test_align_with_known_profiles(self) -> None:
        # Shield profiles are a subset of Redact's recognised profile names.
        assert SHIELD_PROFILES <= KNOWN_PROFILES


# ── AC4: the Protocol boundary + concrete adapters satisfy it ─────────────────
class TestProtocolBoundary:
    def test_adapters_satisfy_protocol_structurally(self) -> None:
        assert isinstance(FixtureShieldAdapter([]), ClassifierProtocol)
        assert isinstance(ShieldAdapter("http://127.0.0.1:8600"), ClassifierProtocol)

    def test_arbitrary_object_with_classify_satisfies(self) -> None:
        class MyClassifier:
            def classify(self, text: str, profile: str) -> list[RedactSpan]:
                return []

        assert isinstance(MyClassifier(), ClassifierProtocol)


# ── AC1 + AC5: classifier DI; fixture → spans → redacted text, no HTTP ─────────
class TestFixtureEndToEnd:
    def test_fixture_spans_flow_into_redact(self) -> None:
        redactor = Redactor(classifier=FixtureShieldAdapter([EMAIL, SSN]))
        result = redactor.redact(TEXT, profile=SHIELD_LEGAL)
        assert result.text == "Email [EMAIL_ADDRESS], SSN [US_SSN]."
        assert "alice@example.com" not in result.text
        assert "123-45-6789" not in result.text

    def test_confidence_policy_drops_low_confidence_spans(self) -> None:
        weak = RedactSpan(category="US_SSN", start=0, end=5, confidence=0.2, text="Email")
        redactor = Redactor(classifier=FixtureShieldAdapter([EMAIL, SSN, weak]))
        # Default threshold 0.5 → weak span ignored, "Email" survives verbatim.
        assert redactor.redact(TEXT, profile=SHIELD_LEGAL).text.startswith("Email ")

    def test_min_confidence_override(self) -> None:
        weak = RedactSpan(category="PERSON", start=0, end=5, confidence=0.2, text="Email")
        redactor = Redactor(classifier=FixtureShieldAdapter([weak]), min_confidence=0.1)
        assert redactor.redact(TEXT, profile=SHIELD_LEGAL).text.startswith("[PERSON]")

    def test_explicit_spans_override_classifier(self) -> None:
        # Passing spans directly bypasses the classifier entirely.
        redactor = Redactor(classifier=FixtureShieldAdapter([EMAIL, SSN]))
        result = redactor.redact(TEXT, spans=[SSN.to_span()], profile=SHIELD_LEGAL)
        assert "alice@example.com" in result.text  # email NOT redacted
        assert "123-45-6789" not in result.text

    def test_no_classifier_no_spans_is_noop(self) -> None:
        assert Redactor().redact(TEXT).text == TEXT

    def test_by_profile_fixture(self) -> None:
        clf = FixtureShieldAdapter(by_profile={SHIELD_LEGAL: [EMAIL], SHIELD_FINANCE: [SSN]})
        assert Redactor(classifier=clf).redact(TEXT, profile=SHIELD_FINANCE).text == (
            "Email alice@example.com, SSN [US_SSN]."
        )

    def test_reversible_via_classifier_round_trips(self) -> None:
        redactor = Redactor(reversible=True, classifier=FixtureShieldAdapter([EMAIL, SSN]))
        result = redactor.redact(TEXT, profile=SHIELD_LEGAL, matter_id="m1")
        assert result.mapping_id is not None
        assert redactor.unredact(result.text, result.mapping_id, "m1") == TEXT


# ── AC4 (real adapter): ShieldAdapter maps HTTP responses, isolates failures ──
class _FakeResponse:
    def __init__(self, payload: dict[str, Any]) -> None:
        self._payload = payload

    def raise_for_status(self) -> None:
        return None

    def json(self) -> dict[str, Any]:
        return self._payload


class _FakeClient:
    """Records the request and returns a canned Shield analyze response."""

    def __init__(self, payload: dict[str, Any]) -> None:
        self._payload = payload
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def post(self, url: str, json: dict[str, Any]) -> _FakeResponse:
        self.calls.append((url, json))
        return _FakeResponse(self._payload)


class TestShieldAdapter:
    def test_maps_entities_and_passes_profile_through(self) -> None:
        client = _FakeClient(
            {"entities": [
                {"category": "EMAIL_ADDRESS", "start": 6, "end": 23, "confidence": 0.98, "text": "alice@example.com"},
                {"category": "US_SSN", "start": 29, "end": 40, "confidence": 0.95, "text": "123-45-6789"},
            ]}
        )
        adapter = ShieldAdapter("http://127.0.0.1:8600/", client=client)
        spans = adapter.classify(TEXT, SHIELD_FINANCE)

        assert [s.category for s in spans] == ["EMAIL_ADDRESS", "US_SSN"]
        # AC3: profile passed straight through to Shield; URL built from base_url.
        (url, payload) = client.calls[0]
        assert url == "http://127.0.0.1:8600/analyze"
        assert payload == {"text": TEXT, "profile": SHIELD_FINANCE}

    def test_end_to_end_through_redactor(self) -> None:
        client = _FakeClient(
            {"entities": [
                {"category": "US_SSN", "start": 29, "end": 40, "confidence": 0.95, "text": "123-45-6789"},
            ]}
        )
        redactor = Redactor(classifier=ShieldAdapter("http://shield.local", client=client))
        assert redactor.redact(TEXT, profile=SHIELD_LEGAL).text == (
            "Email alice@example.com, SSN [US_SSN]."
        )

    def test_transport_failure_is_sanitised(self) -> None:
        class _BoomClient:
            def post(self, url: str, json: dict[str, Any]) -> _FakeResponse:
                raise RuntimeError(f"connection refused to {url} with secret token")

        adapter = ShieldAdapter("http://shield.local", client=_BoomClient())
        with pytest.raises(ClassifierError) as exc:
            adapter.classify(TEXT, SHIELD_LEGAL)
        # Sanitised: the raw cause (URL / token) is not in the surfaced message.
        assert "secret token" not in str(exc.value)
        assert "shield.local" not in str(exc.value)
