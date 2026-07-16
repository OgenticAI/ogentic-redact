"""Latency benchmark for redact_stream (OGE-1221 AC2).

Usage:
    python python/tests/bench_stream.py

Pass criterion: median per-chunk wall-clock time <= 100 ms.
Exits with code 1 if the criterion is not met.
"""

from __future__ import annotations

import statistics
import sys
import textwrap
import time

from ogentic_redact.profile import Profile
from ogentic_redact.stream import redact_stream

_CHUNK_SIZE = 512  # characters
_NUM_CHUNKS = 50

_SAMPLE_TEXT = textwrap.dedent("""\
    Alice Johnson called the office at +1-800-555-0199 and left her email
    alice.johnson@example.com for the follow-up. She mentioned that Robert
    De Niro would join the call next Tuesday. The meeting link was sent to
    hr@ogenticai.com and the invoice was addressed to billing@corp.example.
    Please confirm with John Smith (john.smith@finance.org) by end of day.
    The IP 192.168.1.42 showed suspicious activity; SSN 123-45-6789 was
    flagged in the audit log. IBAN GB29NWBK60161331926819 appeared twice.
""") * 4  # repeat to get > 512 chars


def _make_chunks() -> list[str]:
    chunks = []
    for i in range(_NUM_CHUNKS):
        start = (i * _CHUNK_SIZE) % len(_SAMPLE_TEXT)
        end = start + _CHUNK_SIZE
        if end <= len(_SAMPLE_TEXT):
            chunks.append(_SAMPLE_TEXT[start:end])
        else:
            # Wrap around.
            chunks.append(_SAMPLE_TEXT[start:] + _SAMPLE_TEXT[: end - len(_SAMPLE_TEXT)])
    return chunks


def run_benchmark() -> None:
    profile = Profile()
    chunks = _make_chunks()

    # Pre-warm: load the spaCy model before timing.
    print("Pre-warming analyzer …", flush=True)
    list(redact_stream(chunks[:2], profile))

    print(f"Benchmarking {_NUM_CHUNKS} chunks of ~{_CHUNK_SIZE} chars each …", flush=True)
    latencies_ms: list[float] = []
    for chunk in chunks:
        t0 = time.perf_counter()
        list(redact_stream([chunk], profile))
        latencies_ms.append((time.perf_counter() - t0) * 1000)

    median_ms = statistics.median(latencies_ms)
    p95_ms = sorted(latencies_ms)[int(0.95 * len(latencies_ms))]
    min_ms = min(latencies_ms)
    max_ms = max(latencies_ms)

    print(f"\nResults ({_NUM_CHUNKS} chunks):")
    print(f"  min    = {min_ms:.1f} ms")
    print(f"  median = {median_ms:.1f} ms")
    print(f"  p95    = {p95_ms:.1f} ms")
    print(f"  max    = {max_ms:.1f} ms")

    if median_ms <= 100.0:
        print(f"\nPASS — median {median_ms:.1f} ms <= 100 ms budget")
    else:
        print(f"\nFAIL — median {median_ms:.1f} ms exceeds 100 ms budget", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    run_benchmark()
