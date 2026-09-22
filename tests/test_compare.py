"""Tests for POST /api/v1/audits/compare (regression comparison)."""

import os
import tempfile

import pytest
from fastapi.testclient import TestClient


RLO = "‮"  # U+202E RIGHT-TO-LEFT OVERRIDE opener
LRE = "‪"  # U+202A LEFT-TO-RIGHT EMBEDDING opener
PDF = "‬"  # U+202C POP DIRECTIONAL FORMATTING closer
LRM = "‎"  # U+200E LEFT-TO-RIGHT MARK (no pairing)


@pytest.fixture()
def client(monkeypatch):
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp.close()
    monkeypatch.setenv("BIDI_DB_PATH", tmp.name)
    # import after env is set
    from app import database
    from app.main import app
    database.DB_PATH = tmp.name
    database.init_db(tmp.name)
    with TestClient(app) as c:
        yield c
    os.unlink(tmp.name)


def _audit(client, text, filename=None):
    resp = client.post("/api/v1/audits",
                       json={"text": text, "filename": filename})
    assert resp.status_code == 201
    return resp.json()["id"]


def _compare(client, before_id, after_id):
    return client.post("/api/v1/audits/compare",
                       json={"before_id": before_id, "after_id": after_id})


# ------------------------------------------------------------- validation ---

def test_compare_same_id_is_422(client):
    audit_id = _audit(client, "clean")
    resp = _compare(client, audit_id, audit_id)
    assert resp.status_code == 422
    assert "different" in resp.json()["detail"]


def test_compare_missing_before_is_404(client):
    after_id = _audit(client, "clean")
    resp = _compare(client, 9999, after_id)
    assert resp.status_code == 404
    assert "before_id" in resp.json()["detail"]


def test_compare_missing_after_is_404(client):
    before_id = _audit(client, "clean")
    resp = _compare(client, before_id, 9999)
    assert resp.status_code == 404
    assert "after_id" in resp.json()["detail"]


def test_compare_rejects_invalid_id_shape(client):
    audit_id = _audit(client, "clean")
    # ge=1 constraint -> pydantic 422
    resp = client.post("/api/v1/audits/compare",
                       json={"before_id": 0, "after_id": audit_id})
    assert resp.status_code == 422
    # missing field -> 422
    resp = client.post("/api/v1/audits/compare",
                       json={"before_id": audit_id})
    assert resp.status_code == 422


# --------------------------------------------------------------- unchanged ---

def test_compare_identical_records_not_changed(client):
    before_id = _audit(client, f"{LRE}x{PDF}", "v1.txt")
    after_id = _audit(client, f"{LRE}x{PDF}", "v2.txt")
    resp = _compare(client, before_id, after_id)
    assert resp.status_code == 200
    body = resp.json()
    assert body["changed"] is False
    assert body["before_id"] == before_id
    assert body["after_id"] == after_id
    assert body["controls"]["added"] == []
    assert body["controls"]["removed"] == []
    assert len(body["controls"]["paired"]) == 2  # LRE + PDF
    assert all(p["changes"] == [] for p in body["controls"]["paired"])
    assert body["risk_level"] == {
        "before": "low", "after": "low",
        "direction": "unchanged", "changed": False,
    }
    assert body["error_count"] == {
        "before": 0, "after": 0, "delta": 0, "changed": False,
    }


# ----------------------------------------------------- added / removed ########

def test_compare_reports_added_and_removed(client):
    # before: unclosed LRE (medium); after: lone LRM (info)
    before_id = _audit(client, f"{LRE}a")
    after_id = _audit(client, f"a{LRM}")
    body = _compare(client, before_id, after_id).json()

    removed = body["controls"]["removed"]
    added = body["controls"]["added"]
    assert [r["abbreviation"] for r in removed] == ["LRE"]
    assert [a["abbreviation"] for a in added] == ["LRM"]
    assert removed[0]["before"]["logical_index"] == 0
    assert added[0]["after"]["logical_index"] == 1

    assert body["risk_level"]["before"] == "medium"
    assert body["risk_level"]["after"] == "info"
    assert body["risk_level"]["direction"] == "decreased"
    assert body["risk_level"]["changed"] is True
    assert body["error_count"] == {
        "before": 1, "after": 0, "delta": -1, "changed": True,
    }
    assert body["control_count"]["before"] == 1
    assert body["control_count"]["after"] == 1
    assert body["control_count"]["delta"] == 0
    assert body["changed"] is True


def test_compare_pairing_uses_occurrence_order(client):
    # 3 LRMs before, 1 LRM after -> occurrences 2 and 3 removed, not cross-paired
    before_id = _audit(client, f"{LRM}a{LRM}b{LRM}")
    after_id = _audit(client, f"x{LRM}")
    body = _compare(client, before_id, after_id).json()

    added = body["controls"]["added"]
    removed = body["controls"]["removed"]
    paired = body["controls"]["paired"]
    assert added == []
    assert [(r["abbreviation"], r["occurrence"]) for r in removed] == [
        ("LRM", 2), ("LRM", 3),
    ]
    assert len(paired) == 1
    assert paired[0]["occurrence"] == 1
    # occurrence 1 moved from index 0 to index 1
    assert paired[0]["before"]["logical_index"] == 0
    assert paired[0]["after"]["logical_index"] == 1
    assert paired[0]["position_changed"] is True


# ------------------------------------------------------- position / scope ---

def test_compare_position_only_for_unpaired_mark(client):
    # LRM has no pairing scope; moving it is a pure position change
    before_id = _audit(client, f"a{LRM}")
    after_id = _audit(client, f"{LRM}a")
    body = _compare(client, before_id, after_id).json()

    lrm = body["controls"]["paired"][0]
    assert lrm["abbreviation"] == "LRM"
    assert lrm["changes"] == ["position"]
    assert lrm["position_changed"] is True
    assert lrm["pairing_changed"] is False
    assert body["changed"] is True


def test_compare_pairing_scope_changed_while_opener_stays(client):
    # opener LRE stays at index 0; the closing PDF moves from 2 to 3, so the
    # pairing range [0, scope_end) grows
    before_id = _audit(client, f"{LRE}x{PDF}y")
    after_id = _audit(client, f"{LRE}xy{PDF}")
    body = _compare(client, before_id, after_id).json()

    by_abbr = {p["abbreviation"]: p for p in body["controls"]["paired"]}
    lre = by_abbr["LRE"]
    pdf = by_abbr["PDF"]
    assert lre["before"]["logical_index"] == 0
    assert lre["after"]["logical_index"] == 0
    assert lre["before"]["scope_end"] == 2
    assert lre["after"]["scope_end"] == 3
    assert lre["changes"] == ["pairing"]
    assert lre["pairing_changed"] is True
    # the closer itself only moved
    assert pdf["before"]["logical_index"] == 2
    assert pdf["after"]["logical_index"] == 3
    assert pdf["changes"] == ["position"]


def test_compare_risk_and_errors_when_override_gets_closed(client):
    # unclosed RLO -> critical with 1 error; closed RLO -> high, no errors
    before_id = _audit(client, f"{RLO}bad")
    after_id = _audit(client, f"{RLO}bad{PDF}")
    body = _compare(client, before_id, after_id).json()

    assert body["risk_level"] == {
        "before": "critical", "after": "high",
        "direction": "decreased", "changed": True,
    }
    assert body["error_count"] == {
        "before": 1, "after": 0, "delta": -1, "changed": True,
    }
    assert body["control_count"] == {
        "before": 1, "after": 2, "delta": 1, "changed": True,
    }
    assert [a["abbreviation"] for a in body["controls"]["added"]] == ["PDF"]

    rlo = next(p for p in body["controls"]["paired"]
               if p["abbreviation"] == "RLO")
    assert rlo["before"]["is_orphan"] is True
    assert rlo["after"]["is_orphan"] is False
    assert "orphan" in rlo["changes"]
    assert "pairing" in rlo["changes"]
    assert rlo["risk_changed"] is True
    assert body["changed"] is True


# ---------------------------------------------------------------- summaries ---

def test_compare_returns_both_side_summaries(client):
    before_id = _audit(client, "clean", "before.txt")
    after_id = _audit(client, f"{RLO}x", "after.txt")
    body = _compare(client, before_id, after_id).json()

    before = body["before"]
    after = body["after"]
    assert before["id"] == before_id
    assert before["filename"] == "before.txt"
    assert before["risk_level"] == "info"
    assert after["id"] == after_id
    assert after["filename"] == "after.txt"
    assert after["risk_level"] == "critical"
    # summaries must not leak raw text / full parse results
    assert "raw_text" not in before and "result" not in before
    assert "raw_text" not in after and "result" not in after
    for field in ("created_at", "text_length", "max_depth",
                  "error_count", "control_count"):
        assert field in before and field in after
