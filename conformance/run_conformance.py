"""Safe public binding conformance and separate trusted-adapter map round trips."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

# Import/build failures are failures; CI must not silently skip this surface.
from ogentic_redact._native import (
    _redact_to_mapping_with_salt,
    redact,
    redact_with_salt,
    unredact,
)

_DOC = json.loads((Path(__file__).parent / "vectors.json").read_text())
_VECTORS = _DOC["vectors"]
_SALT = bytes.fromhex(_DOC["call_salt_hex"])
assert _VECTORS and _SALT


@pytest.mark.parametrize("vector", _VECTORS, ids=[v["id"] for v in _VECTORS])
def test_safe_default_conformance(vector: dict[str, Any]) -> None:
    result = redact_with_salt(vector["input"], _SALT)
    assert result["text"] == vector["expected_text"]
    assert set(result) == {"text", "redaction_count"}
    assert set(redact(vector["input"])) == {"text", "redaction_count"}


@pytest.mark.parametrize("vector", _VECTORS, ids=[v["id"] for v in _VECTORS])
def test_private_mapping_adapter_round_trip(vector: dict[str, Any]) -> None:
    result = _redact_to_mapping_with_salt(vector["input"], _SALT)
    assert result["text"] == vector["expected_text"]
    assert result["tokens"] == vector["expected_tokens"]
    assert unredact(result["text"], result["tokens"]) == vector["input"]


def test_default_does_not_expose_original_values() -> None:
    text = "Email alice@example.com; call 555-867-5309; SSN 123-45-6789."
    for result in (redact(text), redact_with_salt(text, _SALT)):
        assert result["redaction_count"] == 3
        payload = json.dumps(result)
        for secret in ("alice@example.com", "555-867-5309", "123-45-6789"):
            assert secret not in payload
