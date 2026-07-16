"""Redaction profile — specifies which entity types to detect and redact."""

from __future__ import annotations

from dataclasses import dataclass, field

__all__ = ["DEFAULT_ENTITY_TYPES", "KNOWN_PROFILES", "Profile"]

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
        entity_types: List of Presidio entity type identifiers to detect.
        language: ISO 639-1 language code for the analyzer (default "en").
    """

    entity_types: list[str] = field(default_factory=lambda: list(DEFAULT_ENTITY_TYPES))
    language: str = "en"

    @classmethod
    def from_shield_profile(cls, name: str) -> Profile:
        """Return a Profile pre-configured for the named Shield workflow profile.

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
