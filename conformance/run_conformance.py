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
    from ogentic_redact._native import redact as _redact  # type: ignore[import]
except ImportError as exc:
    pytest.skip(
        f"ogentic_redact._native not available — run `maturin develop` first. ({exc})",
        allow_module_level=True,
    )


# ── Load vectors ─────────────────────────────────────────────────────────────

_VECTORS_PATH = Path(__file__).parent.parent / "conformance" / "vectors.json"


def _load_vectors() -> list[dict[str, Any]]:
    with _VECTORS_PATH.open(encoding="utf-8") as fh:
        data = json.load(fh)
    assert data.get("vectors"), "vectors.json must contain at least one vector"
    return data["vectors"]


_VECTORS = _load_vectors()


# ── Parametrised test ─────────────────────────────────────────────────────────

@pytest.mark.parametrize("vector", _VECTORS, ids=[v["id"] for v in _VECTORS])
def test_f3_conformance_python(vector: dict[str, Any]) -> None:
    """Each vector must produce byte-identical text and tokens."""
    result = _redact(vector["input"])

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
