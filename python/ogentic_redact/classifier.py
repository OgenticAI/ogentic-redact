"""Classifier boundary — consume pre-classified spans from ogentic-shield (OGE-1230).

Per ADR-0002, Redact does **not** detect entities; it applies redaction *policy*
to spans produced by a classifier (``ogentic-shield``). This module defines that
boundary:

* :class:`RedactSpan` — the canonical, Shield-shaped span the core consumes.
* :class:`ClassifierProtocol` — the ``typing.Protocol`` the core depends on.
* :class:`ShieldAdapter` — the real HTTP adapter over Shield's ``analyze`` surface.
* :class:`FixtureShieldAdapter` — a hardcoded, no-HTTP double for tests and demos.

The core only ever depends on the *protocol*; it never imports Shield or ``httpx``.
The default :class:`~ogentic_redact.redactor.Redactor` path (caller-supplied spans,
no classifier) still makes no network calls, honouring the on-device default
(CLAUDE.md §4). Constructing and using :class:`ShieldAdapter` is the explicit,
opt-in network path.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field

from ogentic_redact.categories import CATEGORY_GROUP_PRECEDENCE
from ogentic_redact.errors import ClassifierError
from ogentic_redact.logging import log_structured
from ogentic_redact.profile import SHIELD_FINANCE, SHIELD_LEGAL
from ogentic_redact.span import Span

if TYPE_CHECKING:
    import httpx

logger = logging.getLogger("ogentic_redact.classifier")

# Shield profile taxonomy (AC3). Re-exported from :mod:`profile` so there is one
# source of truth for the string values.
SHIELD_PROFILES: frozenset[str] = frozenset({SHIELD_LEGAL, SHIELD_FINANCE})

# Precedence tier for a category not present in CATEGORY_GROUP_PRECEDENCE.
# One past the last known tier → lowest precedence in overlap resolution.
_DEFAULT_GROUP: int = len(CATEGORY_GROUP_PRECEDENCE)

# ---------------------------------------------------------------------------
# Confidence policy — "Shield classifies, Redact applies policy".
#
# Shield returns a confidence in [0, 1] for every span. Redact decides which of
# those to actually redact. This threshold is the security ⇄ utility dial:
#   * lower  → redact more, including low-confidence hits (safer, risks over-redaction)
#   * higher → redact only high-confidence hits (cleaner text, risks leaking PII)
# 0.5 is a deliberately middling default; override per-Redactor via
# ``Redactor(min_confidence=...)``.
# ---------------------------------------------------------------------------
DEFAULT_MIN_CONFIDENCE: float = 0.5


class RedactSpan(BaseModel):
    """A classified span consumed from Shield (AC2).

    The canonical shape Shield's ``DetectedEntity`` maps into: a category label,
    a half-open ``[start, end)`` character range, a detection ``confidence``, and
    the matched ``text``. This is the boundary model — the redaction pipeline
    works with the internal :class:`~ogentic_redact.span.Span` produced by
    :meth:`to_span`.
    """

    model_config = ConfigDict(frozen=True)

    category: str = Field(min_length=1)
    start: int = Field(ge=0)
    end: int = Field(gt=0)
    confidence: float = Field(ge=0.0, le=1.0)
    text: str = ""

    @classmethod
    def from_shield_entity(cls, entity: dict[str, Any]) -> RedactSpan:
        """Build a :class:`RedactSpan` from one Shield ``DetectedEntity`` object.

        Accepts Shield's JSON entity shape (``category``, ``start``, ``end``,
        ``confidence``, ``text``); unknown extra keys (``category_group``,
        ``layer``, …) are ignored so Shield can add fields without breaking us.
        """
        try:
            return cls(
                category=str(entity["category"]),
                start=int(entity["start"]),
                end=int(entity["end"]),
                confidence=float(entity.get("confidence", 1.0)),
                text=str(entity.get("text", "")),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ClassifierError("malformed classifier span") from exc

    def to_span(self) -> Span:
        """Convert to the internal :class:`Span` the redactor replaces.

        The ``group`` precedence tier is resolved from the category via
        :data:`~ogentic_redact.categories.CATEGORY_GROUP_PRECEDENCE`
        (PRIVILEGE > PHI > MNPI > PII); an unknown category falls to the lowest
        tier so it never outranks a classified one.
        """
        group = CATEGORY_GROUP_PRECEDENCE.get(self.category.upper(), _DEFAULT_GROUP)
        return Span(start=self.start, end=self.end, entity_type=self.category, group=group)


@runtime_checkable
class ClassifierProtocol(Protocol):
    """The classification boundary the Redact core depends on (AC1 / AC4).

    An implementation returns the pre-classified spans for ``text`` under the
    named ``profile``. Redact never detects entities itself (ADR-0002); it only
    depends on this protocol, so the concrete classifier (real Shield adapter,
    fixture, or a caller's own) is swappable by dependency injection.
    """

    def classify(self, text: str, profile: str) -> list[RedactSpan]:
        """Return classified spans for *text* under *profile*."""
        ...


class ShieldAdapter:
    """Real HTTP adapter over ogentic-shield's ``analyze`` surface (AC4).

    Isolates the Shield API behind :class:`ClassifierProtocol`: it POSTs
    ``{"text", "profile"}`` to ``<base_url>/analyze`` and maps the returned
    ``entities`` array into :class:`RedactSpan` objects. The core never sees
    ``httpx`` or Shield's wire shape.

    Network use is explicit opt-in (CLAUDE.md §4): only callers that construct a
    ``ShieldAdapter`` and pass it to a :class:`~ogentic_redact.redactor.Redactor`
    leave the device. Point ``base_url`` at a localhost Shield to stay on-device.

    Args:
        base_url: Base URL of the Shield analyze service (e.g. ``http://127.0.0.1:8600``).
        timeout: Per-request timeout in seconds.
        client: Optional pre-built ``httpx.Client`` (injected for testing / connection
            reuse). When ``None``, a short-lived client is created per call.
    """

    def __init__(
        self,
        base_url: str,
        *,
        timeout: float = 5.0,
        client: httpx.Client | None = None,
    ) -> None:
        self._url = base_url.rstrip("/") + "/analyze"
        self._timeout = timeout
        self._client = client

    def classify(self, text: str, profile: str) -> list[RedactSpan]:
        """Classify *text* by calling Shield; map ``entities`` → spans.

        Raises:
            ClassifierError: on any transport or response-shape failure. The raw
                cause is logged with context but not surfaced to the caller.
        """
        payload = {"text": text, "profile": profile}
        try:
            data = self._post(payload)
            entities = data.get("entities", [])
            return [RedactSpan.from_shield_entity(e) for e in entities]
        except ClassifierError:
            raise
        except Exception as exc:
            log_structured(
                logging.ERROR,
                "shield classify failed",
                service="ogentic_redact",
                op="classify",
                profile=profile,
                error=str(exc),
            )
            raise ClassifierError("classification request failed") from exc

    def _post(self, payload: dict[str, Any]) -> dict[str, Any]:
        """POST *payload* to the Shield analyze endpoint and return parsed JSON."""
        if self._client is not None:
            resp = self._client.post(self._url, json=payload)
            resp.raise_for_status()
            result: dict[str, Any] = resp.json()
            return result

        try:
            import httpx
        except ImportError as exc:  # pragma: no cover - exercised only without the extra
            raise ClassifierError(
                "ShieldAdapter's HTTP path requires httpx. "
                "Install with: pip install 'ogentic-redact[shield]'"
            ) from exc

        with httpx.Client(timeout=self._timeout) as client:
            resp = client.post(self._url, json=payload)
            resp.raise_for_status()
            parsed: dict[str, Any] = resp.json()
            return parsed


class FixtureShieldAdapter:
    """Hardcoded classifier for tests and demos — no HTTP (AC5).

    Returns pre-baked spans, proving that classified spans flow
    ``fixture → RedactSpan → redact()`` without a live Shield. Supply either a
    single ``spans`` list (returned for every profile) or a ``by_profile`` map
    for profile-specific fixtures.
    """

    def __init__(
        self,
        spans: list[RedactSpan] | None = None,
        *,
        by_profile: dict[str, list[RedactSpan]] | None = None,
    ) -> None:
        self._spans = list(spans or [])
        self._by_profile = {k: list(v) for k, v in (by_profile or {}).items()}

    def classify(self, text: str, profile: str) -> list[RedactSpan]:
        """Return the fixture spans for *profile* (falling back to the default set)."""
        return list(self._by_profile.get(profile, self._spans))
