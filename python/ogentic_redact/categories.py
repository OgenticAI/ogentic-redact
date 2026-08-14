"""Category group precedence — canonical ordering for overlapping span resolution.

The CATEGORY_GROUP_PRECEDENCE constant defines the deterministic precedence order
for resolving overlapping detection spans: PRIVILEGE > PHI > MNPI > PII.

When two spans cover the same or overlapping text, the span belonging to the
higher-precedence category (lower group number) is kept by resolve_overlaps().
"""

from __future__ import annotations

__all__ = ["CATEGORY_GROUP_PRECEDENCE"]

CATEGORY_GROUP_PRECEDENCE: dict[str, int] = {
    "PRIVILEGE": 0,
    "PHI": 1,
    "MNPI": 2,
    "PII": 3,
}
