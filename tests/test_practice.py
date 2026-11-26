"""Practice-format detector tests. Standard library + pytest only."""

import csv
import json
import os
from pathlib import Path

import pytest

from trustverify.practice import load_policy, run

HEADER = ["event_id", "event_time_utc", "received_time_utc", "source_clock_offset_ms", "actor",
          "source_service", "target_service", "action", "role_before", "role_after", "outcome",
          "approval_id", "session_id", "correlation_id"]
TOOLKIT = Path(os.environ.get("TRACK4_TOOLKIT", Path(__file__).resolve().parents[2] / "Track-4-Toolkit")) / "practice"


def write(directory, rows, approvals):
    directory.mkdir(exist_ok=True)
    with open(directory / "events.csv", "w", newline="") as stream:
        writer = csv.writer(stream)
        writer.writerow(HEADER)
        writer.writerows(rows)
    (directory / "approvals.json").write_text(json.dumps({"changes": approvals}))
    return run(directory)


def row(eid, second, actor, src, dst, action, before, after, outcome, approval="", session="s1", flow="f1",
        received=None, offset=0):
    t = f"2026-01-15T09:00:{second:02d}.000Z"
    return [eid, t, received or t, offset, actor, src, dst, action, before, after, outcome, approval, session, flow]


GRANT = {"approval_id": "c1", "approved_by": "admin", "subject": "eve", "operation": "grant_role",
         "role": "report-reader", "scope": ["reports"], "valid_from_utc": "2026-01-15T09:00:00Z",
         "valid_until_utc": "2026-01-15T09:00:30Z"}


def rules(result):
    return [(a["rule"], a["events"]) for a in result["alerts"]]


def test_self_approved_role_change_is_flagged(tmp_path):
    self_grant = {**GRANT, "approved_by": "eve"}
    result = write(tmp_path / "d", [
        row("a1", 1, "eve", "admin-console", "identity", "approve_role_change", "operator", "operator", "success", "c1"),
        row("a2", 2, "eve", "admin-console", "identity", "role_change", "viewer", "report-reader", "success", "c1")],
        [self_grant])
    assert ("unapproved_role_change", ["a2"]) in rules(result)


def test_approval_window_is_exclusive_and_needs_the_approval_event(tmp_path):
    late = write(tmp_path / "late", [
        row("b1", 1, "admin", "admin-console", "identity", "approve_role_change", "operator", "operator", "success", "c1"),
        row("b2", 30, "eve", "admin-console", "identity", "role_change", "viewer", "report-reader", "success", "c1")],
        [GRANT])
    assert ("unapproved_role_change", ["b2"]) in rules(late)
    missing = write(tmp_path / "missing", [
        row("c2", 5, "eve", "admin-console", "identity", "role_change", "viewer", "report-reader", "success", "c1")],
        [GRANT])
    assert ("unapproved_role_change", ["c2"]) in rules(missing)


def test_isolated_edge_is_a_notice_but_a_sequence_alerts_with_valid_credentials(tmp_path):
    result = write(tmp_path / "d", [
        row("d1", 1, "svc", "reports", "billing", "read", "service-reader", "service-reader", "allow", flow="x"),
        row("d2", 2, "carol", "portal", "billing", "read", "viewer", "viewer", "deny", session="s2", flow="y"),
        row("d3", 3, "svc", "billing", "secrets", "read", "service-reader", "service-reader", "allow", flow="x")],
        [])
    assert rules(result) == [("lateral_movement_sequence", ["d1", "d3"])]
    assert {n["event_id"] for n in result["notices"] if n["notice"] == "isolated_unexpected_edge"} == {"d1", "d2"}


def test_reordered_and_offset_events_produce_timing_notices(tmp_path):
    result = write(tmp_path / "d", [
        row("e2", 10, "eve", "portal", "catalog", "read", "viewer", "viewer", "allow"),
        row("e1", 5, "eve", "portal", "catalog", "read", "viewer", "viewer", "allow", received="2026-01-15T09:00:11.000Z"),
        row("e3", 20, "eve", "portal", "catalog", "read", "viewer", "viewer", "allow",
            received="2026-01-15T09:00:18.500Z", offset=2000)],
        [])
    kinds = {(n["event_id"], n["notice"]) for n in result["notices"]}
    assert ("e1", "out_of_order_arrival") in kinds and ("e3", "clock_offset_corrected") in kinds
    assert result["alerts"] == []


def test_policy_never_grants_scope_that_needs_an_approval():
    policy = load_policy()
    assert ("portal", "reports") not in policy["report-reader"]


@pytest.mark.skipif(not (TOOLKIT / "events.csv").exists(), reason="toolkit practice data not checked out")
def test_toolkit_practice_events_match_published_labels():
    evaluation = run(TOOLKIT)["evaluation"]
    mismatches = [r for r in evaluation["per_event"]
                  if r["flagged"] != (r["label"] in evaluation["positive_labels"])]
    assert mismatches == []
