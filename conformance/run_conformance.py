"""F3 cross-language conformance test — Python surface.

Loads ``conformance/vectors.json`` from the repo root and verifies that
``ogentic_redact._native.redact`` produces byte-identical output to the
expected values.  Any divergence is a pytest failure (→ CI red).

Run (from repo root, after ``maturin develop``):
    pytest conformance/run_conformance.py -v
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

# ── Import the Rust-backed binding ───────────────────────────────────────────

try:
    from ogentic_redact._native import (  # type: ignore[import]
        redact_with_salt as _redact_with_salt,
        unredact as _unredact,
    )
except ImportError as exc:
    pytest.skip(
        f"ogentic_redact._native not available — run `maturin develop` first. ({exc})",
        allow_module_level=True,
    )


# ── Load vectors ─────────────────────────────────────────────────────────────

_VECTORS_PATH = Path(__file__).parent.parent / "conformance" / "vectors.json"


def _load_doc() -> dict[str, Any]:
    with _VECTORS_PATH.open(encoding="utf-8") as fh:
        data = json.load(fh)
    assert data.get("vectors"), "vectors.json must contain at least one vector"
    assert data.get("call_salt_hex"), "vectors.json must carry a fixed call_salt_hex"
    return data


_DOC = _load_doc()
_VECTORS = _DOC["vectors"]
_SALT = bytes.fromhex(_DOC["call_salt_hex"])


# ── Parametrised test ─────────────────────────────────────────────────────────

@pytest.mark.parametrize("vector", _VECTORS, ids=[v["id"] for v in _VECTORS])
def test_f4_conformance_python(vector: dict[str, Any]) -> None:
    """Each vector must produce byte-identical text/tokens under the fixed salt,
    and round-trip back to the original input (ADR-0003 §9)."""
    result = _redact_with_salt(vector["input"], _SALT)

    assert result["text"] == vector["expected_text"], (
        f"[{vector['id']}] text mismatch\n"
        f"  input:    {vector['input']!r}\n"
        f"  got:      {result['text']!r}\n"
        f"  expected: {vector['expected_text']!r}"
    )
    assert result["tokens"] == vector["expected_tokens"], (
        f"[{vector['id']}] tokens mismatch\n"
        f"  input:    {vector['input']!r}\n"
        f"  got:      {result['tokens']!r}\n"
        f"  expected: {vector['expected_tokens']!r}"
    )

    restored = _unredact(result["text"], result["tokens"])
    assert restored == vector["input"], (
        f"[{vector['id']}] round-trip mismatch\n"
        f"  got:      {restored!r}\n"
        f"  expected: {vector['input']!r}"
    )
