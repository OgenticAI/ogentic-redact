"""Redaction profile — specifies which entity types to detect and redact."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

__all__ = [
    "DEFAULT_ENTITY_TYPES",
    "KNOWN_PROFILES",
    "SHIELD_FINANCE",
    "SHIELD_LEGAL",
    "Profile",
]

# Shield profile taxonomy (OGE-1230 AC3) — first-class constants so callers and
# adapters reference names symbolically rather than by bare string literal. These
# are the profile ids the Shield adapter passes straight through to Shield.
SHIELD_LEGAL = "shield-legal"
SHIELD_FINANCE = "shield-finance"

DEFAULT_ENTITY_TYPES: list[str] = [
    "PERSON",
    "PHONE_NUMBER",
    "EMAIL_ADDRESS",
    "LOCATION",
    "CREDIT_CARD",
    "IBAN_CODE",
    "IP_ADDRESS",
    "URL",
    "US_SSN",
    "MEDICAL_LICENSE",
]

# Legal-domain entity types surfaced by ogentic-shield's legal recognisers.
_CASE_NUMBER = "CASE_NUMBER"
_BATES_NUMBER = "BATES_NUMBER"

# Mapping of Shield profile name → entity types the redactor will act on.
# This is workflow policy, not detection logic — Shield detects, Redact filters.
# Extend this dict to add new profiles; do NOT add detection code here.
_KNOWN_PROFILES: dict[str, list[str]] = {
    "shield-legal": [*DEFAULT_ENTITY_TYPES, _CASE_NUMBER, _BATES_NUMBER],
    "shield-finance": list(DEFAULT_ENTITY_TYPES),
}

# Public read-only view of profile names (useful for validation in callers).
KNOWN_PROFILES: frozenset[str] = frozenset(_KNOWN_PROFILES)


@dataclass
class Profile:
    """Defines which entity types the redactor will detect and redact.

    Attributes:
        entity_types: Explicit list of entity identifiers to detect. An empty
            list disables detection. Local streaming rejects any requested
            entity that its installed analyzer does not support.
        language: ISO 639-1 language code for the analyzer (default "en").
    """

    entity_types: list[str] = field(default_factory=lambda: list(DEFAULT_ENTITY_TYPES))
    language: str = "en"

    def __post_init__(self) -> None:
        self.validate()

    def validate(self) -> None:
        """Validate configuration, including lists mutated after construction."""
        if not isinstance(self.entity_types, list) or any(
            not isinstance(entity, str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,127}", entity)
            for entity in self.entity_types
        ):
            raise ValueError("entity_types must be a list of valid entity identifiers")
        if not isinstance(self.language, str) or not self.language:
            raise ValueError("language must be a non-empty string")

    @classmethod
    def from_shield_profile(cls, name: str) -> Profile:
        """Return the requested entity policy for a named Shield workflow.

        This does not install or register recognizers. In particular, the stock
        local streaming analyzer lacks CASE_NUMBER and BATES_NUMBER and rejects
        the legal policy. Use ``Redactor`` with a ``ShieldAdapter`` to obtain
        Shield's domain detections.

        Args:
            name: Shield profile identifier, e.g. ``"shield-legal"`` or
                ``"shield-finance"``.

        Returns:
            A :class:`Profile` whose ``entity_types`` reflect the workflow
            policy for that profile.

        Raises:
            ValueError: If *name* is not a recognised Shield profile.  The
                error message lists valid names but does not expose internals.
        """
        if name not in _KNOWN_PROFILES:
            known = ", ".join(sorted(_KNOWN_PROFILES))
            raise ValueError(
                f"Unknown Shield profile {name!r}. "
                f"Valid profiles are: {known}."
            )
        return cls(entity_types=list(_KNOWN_PROFILES[name]))
