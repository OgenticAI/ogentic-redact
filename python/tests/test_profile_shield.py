"""Acceptance tests for category-aware Shield profile defaults (OGE-1214 / REDACT-R4).

AC1: shield-legal profile redacts CaseNumber and BatesNumber by default.
AC2: shield-finance profile does NOT redact CaseNumber/BatesNumber by default.
AC3: Profiles are declarative config, decoupled from Shield detection logic.
AC4: Unknown profile name rejected with sanitised error before any processing.
AC5: Test covering the legal vs finance divergence on identical input scope.
"""

from __future__ import annotations

import pytest

from ogentic_redact.profile import (
    DEFAULT_ENTITY_TYPES,
    KNOWN_PROFILES,
    Profile,
)

# ---------------------------------------------------------------------------
# AC1 — shield-legal profile includes CaseNumber and BatesNumber
# ---------------------------------------------------------------------------


class TestAC1LegalProfileIncludesLegalTypes:
    def test_case_number_in_shield_legal(self) -> None:
        profile = Profile.from_shield_profile("shield-legal")
        assert "CASE_NUMBER" in profile.entity_types

    def test_bates_number_in_shield_legal(self) -> None:
        profile = Profile.from_shield_profile("shield-legal")
        assert "BATES_NUMBER" in profile.entity_types

    def test_shield_legal_includes_all_defaults(self) -> None:
        """shield-legal is a superset of the default entity types."""
        profile = Profile.from_shield_profile("shield-legal")
        for entity in DEFAULT_ENTITY_TYPES:
            assert entity in profile.entity_types, (
                f"Expected {entity!r} in shield-legal entity_types"
            )

    def test_shield_legal_returns_profile_instance(self) -> None:
        profile = Profile.from_shield_profile("shield-legal")
        assert isinstance(profile, Profile)


# ---------------------------------------------------------------------------
# AC2 — shield-finance profile does NOT include CaseNumber/BatesNumber
# ---------------------------------------------------------------------------


class TestAC2FinanceProfileExcludesLegalTypes:
    def test_case_number_not_in_shield_finance(self) -> None:
        profile = Profile.from_shield_profile("shield-finance")
        assert "CASE_NUMBER" not in profile.entity_types

    def test_bates_number_not_in_shield_finance(self) -> None:
        profile = Profile.from_shield_profile("shield-finance")
        assert "BATES_NUMBER" not in profile.entity_types

    def test_shield_finance_has_default_types(self) -> None:
        profile = Profile.from_shield_profile("shield-finance")
        assert set(profile.entity_types) == set(DEFAULT_ENTITY_TYPES)


# ---------------------------------------------------------------------------
# AC3 — Profiles are declarative config, decoupled from detection logic
# ---------------------------------------------------------------------------


class TestAC3DeclarativeConfig:
    def test_profile_entity_types_is_a_list_of_strings(self) -> None:
        """Profiles are plain data — no callables or recognizer objects embedded."""
        for name in KNOWN_PROFILES:
            profile = Profile.from_shield_profile(name)
            assert isinstance(profile.entity_types, list)
            for item in profile.entity_types:
                assert isinstance(item, str), (
                    f"entity_types entry {item!r} in {name!r} is not a string"
                )

    def test_profiles_do_not_share_mutable_state(self) -> None:
        """Mutating one profile's entity_types must not affect another."""
        legal = Profile.from_shield_profile("shield-legal")
        finance = Profile.from_shield_profile("shield-finance")
        original_finance_count = len(finance.entity_types)

        legal.entity_types.append("__SENTINEL__")

        assert len(finance.entity_types) == original_finance_count, (
            "shield-finance entity_types was mutated when shield-legal was modified"
        )
        assert "__SENTINEL__" not in finance.entity_types

    def test_from_shield_profile_returns_independent_copy(self) -> None:
        """Each call returns a fresh list — caller mutations are isolated."""
        a = Profile.from_shield_profile("shield-legal")
        b = Profile.from_shield_profile("shield-legal")
        a.entity_types.clear()
        assert len(b.entity_types) > 0, (
            "Clearing one profile's list must not affect another returned by the same factory"
        )


# ---------------------------------------------------------------------------
# AC4 — Unknown profile rejected with sanitised error before any processing
# ---------------------------------------------------------------------------


class TestAC4UnknownProfileRejected:
    def test_unknown_profile_raises_value_error(self) -> None:
        with pytest.raises(ValueError):
            Profile.from_shield_profile("shield-unknown")

    def test_error_message_is_sanitised_not_internal(self) -> None:
        """The error message must name valid profiles but not expose internals."""
        with pytest.raises(ValueError, match="shield-legal") as exc_info:
            Profile.from_shield_profile("not-a-real-profile")
        msg = str(exc_info.value)
        # Must not expose raw Python internals (tracebacks, object reprs, paths).
        assert "Traceback" not in msg
        assert "/Users/" not in msg

    def test_error_lists_known_profiles(self) -> None:
        with pytest.raises(ValueError) as exc_info:
            Profile.from_shield_profile("shield-xyz")
        msg = str(exc_info.value)
        for name in KNOWN_PROFILES:
            assert name in msg, f"Expected known profile {name!r} listed in error: {msg!r}"

    def test_empty_string_profile_rejected(self) -> None:
        with pytest.raises(ValueError):
            Profile.from_shield_profile("")

    def test_none_like_string_rejected(self) -> None:
        with pytest.raises(ValueError):
            Profile.from_shield_profile("None")


# ---------------------------------------------------------------------------
# AC5 — legal vs finance divergence on identical input
# ---------------------------------------------------------------------------


class TestAC5LegalFinanceDivergence:
    def test_entity_type_sets_differ(self) -> None:
        """shield-legal and shield-finance must target different entity type sets."""
        legal = Profile.from_shield_profile("shield-legal")
        finance = Profile.from_shield_profile("shield-finance")
        assert set(legal.entity_types) != set(finance.entity_types)

    def test_legal_is_strict_superset_of_finance(self) -> None:
        """Every entity type in shield-finance must also be in shield-legal."""
        legal = Profile.from_shield_profile("shield-legal")
        finance = Profile.from_shield_profile("shield-finance")
        assert set(finance.entity_types).issubset(set(legal.entity_types)), (
            "shield-finance contains types not present in shield-legal"
        )

    def test_legal_adds_exactly_case_and_bates(self) -> None:
        """The difference between shield-legal and shield-finance is only the two legal types."""
        legal = Profile.from_shield_profile("shield-legal")
        finance = Profile.from_shield_profile("shield-finance")
        extra = set(legal.entity_types) - set(finance.entity_types)
        assert extra == {"CASE_NUMBER", "BATES_NUMBER"}, (
            f"Unexpected extra types in shield-legal vs shield-finance: {extra}"
        )

    def test_identical_text_yields_different_active_types(self) -> None:
        """Given the same document, shield-legal and shield-finance target different types.

        This verifies policy divergence at the Profile level (before any detection
        engine is called), ensuring the two profiles produce different redaction
        scopes for identical input.
        """
        legal = Profile.from_shield_profile("shield-legal")
        finance = Profile.from_shield_profile("shield-finance")

        # shield-legal will attempt to redact CASE_NUMBER and BATES_NUMBER from doc.
        # shield-finance will not — those types are absent from its entity_types.
        legal_covers_case = "CASE_NUMBER" in legal.entity_types
        finance_covers_case = "CASE_NUMBER" in finance.entity_types

        assert legal_covers_case is True
        assert finance_covers_case is False
