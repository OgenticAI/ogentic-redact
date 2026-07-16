"""Redaction profile — specifies which entity types to detect and redact."""

from __future__ import annotations

from dataclasses import dataclass, field

__all__ = ["DEFAULT_ENTITY_TYPES", "Profile"]

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


@dataclass
class Profile:
    """Defines which entity types the redactor will detect and redact.

    Attributes:
        entity_types: List of Presidio entity type identifiers to detect.
        language: ISO 639-1 language code for the analyzer (default "en").
    """

    entity_types: list[str] = field(default_factory=lambda: list(DEFAULT_ENTITY_TYPES))
    language: str = "en"
