"""Redactor — core redaction engine for ogentic-redact."""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass, field

from ogentic_redact.span import Span


@dataclass
class RedactResult:
    """Result of a single :meth:`Redactor.redact` call.

    Attributes:
        text: The redacted text.
        vault: Mapping from token to original value.  Only populated when
            :class:`Redactor` was constructed with ``reversible=True``.
    """

    text: str
    vault: dict[str, str] = field(default_factory=dict)


class Redactor:
    """Redact sensitive spans from text.

    Two modes are supported:

    * **One-way** (default): each span is replaced with a bracketed entity
      label, e.g. ``[EMAIL]``.  The original value cannot be recovered.
    * **Reversible** (``reversible=True``): each span is replaced with a
      salted opaque token, e.g. ``[RTKN_3a7f9c12ab01]``, and the
      :attr:`RedactResult.vault` mapping token→original is returned.  The
      vault is never stored inline — callers own the vault lifecycle.

    Salt semantics:
        A fresh 128-bit random salt is generated on every :meth:`redact`
        call, so the same value produces *different* tokens across calls.
        Within a single call the salt is fixed, so the same value always
        maps to the same token (within-call stability).
    """

    def __init__(self, reversible: bool = False) -> None:
        self.reversible = reversible

    def redact(self, text: str, spans: list[Span] | None = None) -> RedactResult:
        """Redact *spans* from *text*.

        Args:
            text: Source string to redact.
            spans: Entity spans to replace.  Overlapping spans are resolved
                before replacement; see :meth:`resolve_overlaps`.

        Returns:
            A :class:`RedactResult` with the redacted text and, in reversible
            mode, the token→original vault.

        Raises:
            TypeError: If *text* is not a :class:`str`.
            ValueError: If any span has ``start < 0``, ``end > len(text)``,
                or ``start >= end``.
        """
        if not isinstance(text, str):
            raise TypeError(f"text must be str, got {type(text).__name__!r}")

        spans = spans or []

        for span in spans:
            if span.start < 0 or span.end > len(text) or span.start >= span.end:
                raise ValueError(
                    f"Invalid span [{span.start}:{span.end}] for text of length {len(text)}"
                )

        resolved = self.resolve_overlaps(spans)

        # Per-call salt: ensures tokens differ across independent calls.
        salt = os.urandom(16).hex()

        vault: dict[str, str] = {}
        # Within-call stability: same (value, entity_type) → same token.
        _seen: dict[tuple[str, str], str] = {}

        # Replace right-to-left so earlier indices stay valid.
        for span in sorted(resolved, key=lambda s: s.start, reverse=True):
            value = text[span.start : span.end]

            if self.reversible:
                key = (value, span.entity_type)
                if key not in _seen:
                    digest = hashlib.sha256(
                        f"{salt}:{value}:{span.entity_type}".encode()
                    ).hexdigest()[:12]
                    token = f"[RTKN_{digest}]"
                    _seen[key] = token
                    vault[token] = value
                else:
                    token = _seen[key]
            else:
                token = f"[{span.entity_type}]"

            text = text[: span.start] + token + text[span.end :]

        return RedactResult(text=text, vault=vault)

    def unredact(self, redacted_text: str, vault: dict[str, str]) -> str:
        """Restore original text from *redacted_text* using *vault*.

        Args:
            redacted_text: A string previously returned by :meth:`redact`.
            vault: The :attr:`RedactResult.vault` from the same call.

        Returns:
            The original text with all tokens substituted back.

        Raises:
            ValueError: If the :class:`Redactor` was not created with
                ``reversible=True``.
            TypeError: If *redacted_text* is not a :class:`str`.
            KeyError: If a vault token is not present in *redacted_text*.
        """
        if not self.reversible:
            raise ValueError("unredact() requires Redactor(reversible=True)")
        if not isinstance(redacted_text, str):
            raise TypeError(
                f"redacted_text must be str, got {type(redacted_text).__name__!r}"
            )

        result = redacted_text
        for token, original in vault.items():
            if token not in result:
                raise KeyError(f"Token {token!r} not found in redacted text")
            result = result.replace(token, original)

        return result

    @staticmethod
    def resolve_overlaps(spans: list[Span]) -> list[Span]:
        """Return a non-overlapping subset of *spans*.

        When two spans overlap, the one with the **lower group** number
        (higher precedence) is kept.  For equal groups the span with the
        earlier start position is kept.  The returned list is sorted by
        ``start`` ascending.

        Args:
            spans: Arbitrary collection of :class:`Span` objects.

        Returns:
            A list of non-overlapping :class:`Span` objects sorted by start
            position.
        """
        if not spans:
            return []

        # Process highest-priority spans first (lowest group, then earliest start).
        by_priority = sorted(spans, key=lambda s: (s.group, s.start))

        accepted: list[Span] = []
        covered: list[tuple[int, int]] = []

        for span in by_priority:
            if not any(span.start < end and span.end > start for start, end in covered):
                accepted.append(span)
                covered.append((span.start, span.end))

        return sorted(accepted, key=lambda s: s.start)
