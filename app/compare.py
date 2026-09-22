"""Regression comparison between two stored audit records.

Control characters are paired by abbreviation and order of occurrence:
the n-th occurrence of a given abbreviation (e.g. the 2nd ``RLO``) in the
"before" record is paired with the n-th occurrence of the same abbreviation
in the "after" record. Occurrences without a counterpart are reported as
removed / added; paired occurrences are diffed for position, pairing scope
and per-character risk changes.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Optional

from .database import SUMMARY_FIELDS

# Lowest -> highest, mirrors RiskLevel in bidi.py
RISK_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _view(control: dict) -> dict:
    """Compact projection of one control hit, used in comparison output."""
    return {
        "codepoint": control["codepoint"],
        "abbreviation": control["abbreviation"],
        "kind": control["kind"],
        "logical_index": control["logical_index"],
        "position": {
            "line": control["position"]["line"],
            "column": control["position"]["column"],
        },
        "depth_after": control["depth_after"],
        "scope_end": control["scope_end"],
        "paired_with": control["paired_with"],
        "is_orphan": control["is_orphan"],
        "risk": control["risk"],
    }


def _group_by_abbreviation(controls: list[dict]) -> dict[str, list[dict]]:
    """Group control hits by abbreviation, preserving occurrence order."""
    groups: dict[str, list[dict]] = defaultdict(list)
    for control in controls:
        groups[control["abbreviation"]].append(control)
    return groups


def _unpaired_entry(abbr: str, occurrence: int, control: dict,
                    side: str) -> dict:
    return {
        "abbreviation": abbr,
        "occurrence": occurrence,
        side: _view(control),
    }


def _paired_entry(abbr: str, occurrence: int,
                  before: dict, after: dict) -> dict:
    before_view = _view(before)
    after_view = _view(after)

    changes: list[str] = []
    if before_view["logical_index"] != after_view["logical_index"]:
        changes.append("position")
    if (before_view["scope_end"], before_view["paired_with"]) != \
            (after_view["scope_end"], after_view["paired_with"]):
        changes.append("pairing")
    if before_view["is_orphan"] != after_view["is_orphan"]:
        changes.append("orphan")
    if before_view["depth_after"] != after_view["depth_after"]:
        changes.append("depth")
    if before_view["risk"] != after_view["risk"]:
        changes.append("risk")

    return {
        "abbreviation": abbr,
        "occurrence": occurrence,
        "before": before_view,
        "after": after_view,
        "changes": changes,
        "position_changed": "position" in changes,
        "pairing_changed": "pairing" in changes,
        "risk_changed": "risk" in changes,
    }


def _risk_comparison(before_level: str, after_level: str) -> dict:
    before_rank = RISK_ORDER[before_level]
    after_rank = RISK_ORDER[after_level]
    if after_rank > before_rank:
        direction = "increased"
    elif after_rank < before_rank:
        direction = "decreased"
    else:
        direction = "unchanged"
    return {
        "before": before_level,
        "after": after_level,
        "direction": direction,
        "changed": before_level != after_level,
    }


def _count_comparison(before_count: int, after_count: int) -> dict:
    return {
        "before": before_count,
        "after": after_count,
        "delta": after_count - before_count,
        "changed": before_count != after_count,
    }


def compare_records(before: dict, after: dict) -> dict:
    """Compare two full audit records as returned by ``database.get_audit``."""
    before_groups = _group_by_abbreviation(before["result"]["controls"])
    after_groups = _group_by_abbreviation(after["result"]["controls"])

    added: list[dict] = []
    removed: list[dict] = []
    paired: list[dict] = []
    any_pair_changed = False

    # Stable abbreviation order in the report (sorted alphabetically).
    for abbr in sorted(set(before_groups) | set(after_groups)):
        before_hits = before_groups.get(abbr, [])
        after_hits = after_groups.get(abbr, [])
        for occurrence in range(1, max(len(before_hits), len(after_hits)) + 1):
            b_hit: Optional[dict] = (
                before_hits[occurrence - 1]
                if occurrence <= len(before_hits) else None
            )
            a_hit: Optional[dict] = (
                after_hits[occurrence - 1]
                if occurrence <= len(after_hits) else None
            )
            if b_hit is None:
                added.append(_unpaired_entry(
                    abbr, occurrence, a_hit, "after"))  # type: ignore[arg-type]
            elif a_hit is None:
                removed.append(_unpaired_entry(abbr, occurrence, b_hit, "before"))
            else:
                entry = _paired_entry(abbr, occurrence, b_hit, a_hit)
                paired.append(entry)
                if entry["changes"]:
                    any_pair_changed = True

    # Imported lazily to avoid a circular dependency at module load time.
    before_summary = {k: before[k] for k in SUMMARY_FIELDS}
    after_summary = {k: after[k] for k in SUMMARY_FIELDS}

    risk = _risk_comparison(
        before_summary["risk_level"], after_summary["risk_level"])
    error_count = _count_comparison(
        before_summary["error_count"], after_summary["error_count"])
    control_count = _count_comparison(
        before_summary["control_count"], after_summary["control_count"])

    changed = (
        risk["changed"]
        or error_count["changed"]
        or bool(added)
        or bool(removed)
        or any_pair_changed
    )

    return {
        "before_id": before["id"],
        "after_id": after["id"],
        "changed": changed,
        "before": before_summary,
        "after": after_summary,
        "risk_level": risk,
        "error_count": error_count,
        "control_count": control_count,
        "controls": {
            "added": added,
            "removed": removed,
            "paired": paired,
        },
    }
