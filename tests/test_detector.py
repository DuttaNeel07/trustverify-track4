import copy

import pytest

from scripts.make_fixture import make_events, make_heldout_events
from trustverify.detector import analyze, evaluate


@pytest.mark.parametrize("seed", [2026, 41, 987])
def test_labelled_metrics_and_approved_context(seed):
    events = make_events(seed)
    report = evaluate(events)
    assert report["f1"] == 1.0
    assert report["false_alerts_per_1000_benign_events"] == 0
    assert report["malicious_events"] == 70
    assert report["false_negatives"] == 0
    assert 0 <= report["median_time_to_alert_seconds"] <= 60
    result = analyze(events)
    assert len(result["timing_notices"]) == 2
    assert all(a["identity"].startswith(("compromised-", "lateral-only-")) for a in result["alerts"])
    assert all(a["services"] and a["events"] and a["rule"] and a["explanation"] for a in result["alerts"])


def test_detector_never_reads_labels():
    events = make_events()
    changed = copy.deepcopy(events)
    for event in changed:
        event["malicious"] = not event["malicious"]
    assert analyze(events) == analyze(changed)


def test_untrusted_clock_does_not_hide_revoked_use():
    event = {"id": "late", "actor": "alice", "action": "access", "outcome": "denied",
             "service": "secrets", "details": {"reason": "revoked device"},
             "observed_at": 300, "source_at": 0, "clock_offset": 0,
             "clock_offset_trusted": True}
    result = analyze([event])
    assert len(result["timing_notices"]) == 1
    assert result["alerts"][0]["rule"] == "revoked_credential_use"


def test_duplicate_event_ids_are_rejected():
    events = make_events()[:1]
    with pytest.raises(ValueError, match="unique"):
        analyze(events * 2)


def test_unapproved_regrant_cannot_reuse_prior_approval_context():
    def event(event_id, occurred, actor, action, service, details=None):
        return {"id": event_id, "observed_at": occurred, "actor": actor,
                "action": action, "service": service, "outcome": "allowed", "details": details or {}}
    events = [event("approved", 0, "operator", "grant", "frontend", {"owner": "alice", "target_service": "secrets", "approved": True}),
              event("removed", 1, "operator", "remove_permission", "frontend", {"owner": "alice", "target_service": "secrets"}),
              event("unapproved", 2, "operator", "grant", "frontend", {"owner": "alice", "target_service": "secrets", "approved": False}),
              event("from", 3, "alice", "access", "frontend"),
              event("to", 4, "alice", "access", "secrets")]
    alerts = analyze(events)["alerts"]
    assert {a["rule"] for a in alerts} == {"unapproved_privilege_grant", "unexpected_service_transition"}


@pytest.mark.parametrize("clock", [
    {"source_at": 10, "clock_offset": 0, "clock_offset_trusted": False},
    {"source_at": 131, "clock_offset": 121, "clock_offset_trusted": True},
    {"source_at": -100, "clock_offset": 0, "clock_offset_trusted": True},
])
def test_uncertain_access_cannot_establish_a_definite_path(clock):
    def access(event_id, actor, service, arrival):
        return {"id": event_id, "actor": actor, "service": service,
                "action": "access", "outcome": "allowed", "observed_at": arrival}
    events = [access("a1", "alice", "frontend", 0),
              access("b1", "bob", "frontend", 1),
              {**access("uncertain", "alice", "billing", 10), **clock},
              access("a2", "alice", "secrets", 20),
              access("b2", "bob", "secrets", 21),
              {**access("revoked", "alice", "secrets", 22), "outcome": "denied",
               "details": {"reason": "revoked device"}}]
    result = analyze(events)
    paths = [a for a in result["alerts"] if a["rule"] == "unexpected_service_transition"]
    assert [a["identity"] for a in paths] == ["bob"]
    assert any(a["rule"] == "revoked_credential_use" for a in result["alerts"])
    assert result["timing_notices"][0]["identity"] == "alice"


def test_repeated_equal_times_do_not_reestablish_an_ambiguous_path():
    events = [{"id": index, "actor": "alice", "action": "access", "outcome": "allowed",
               "service": service, "observed_at": arrival, "source_at": occurred,
               "clock_offset": 0, "clock_offset_trusted": True}
              for index, (service, occurred, arrival) in enumerate([
                  ("frontend", 0, 0), ("secrets", 0, 1),
                  ("secrets", 0, 2), ("frontend", 1, 3)])]
    result = analyze(events)
    assert not result["alerts"]
    assert result["timing_notices"]


def test_uncertain_event_still_advances_the_trusted_collector_watermark():
    events = [{"id": "grant", "actor": "operator", "action": "grant", "outcome": "allowed",
               "service": "frontend", "observed_at": 0,
               "details": {"owner": "alice", "target_service": "secrets", "approved": False}},
              {"id": "uncertain", "actor": "bob", "action": "access", "outcome": "allowed",
               "service": "billing", "observed_at": 100, "source_at": 0,
               "clock_offset": 0, "clock_offset_trusted": False}]
    assert analyze(events)["alerts"][0]["alert_at"] == 100


def test_uncertain_denied_grant_needs_no_beneficiary_metadata():
    event = {"id": "denied", "actor": "alice", "action": "grant", "outcome": "denied",
             "service": "frontend", "observed_at": 100, "source_at": 0,
             "clock_offset_trusted": False, "details": {"reason": "administrator required"}}
    result = analyze([event])
    assert not result["alerts"]
    assert result["timing_notices"][0]["path_alerts_suppressed_for_batch"] == ["alice"]


@pytest.mark.parametrize("action", ["grant", "remove_permission"])
def test_uncertain_permission_change_also_marks_the_beneficiary(action):
    events = [{"id": "permission", "actor": "operator", "action": action, "outcome": "allowed",
               "service": "frontend", "observed_at": 0, "source_at": 0,
               "clock_offset_trusted": False,
               "details": {"owner": "alice", "target_service": "secrets", "approved": True}},
              {"id": "from", "actor": "alice", "action": "access", "outcome": "allowed",
               "service": "frontend", "observed_at": 1},
              {"id": "to", "actor": "alice", "action": "access", "outcome": "allowed",
               "service": "secrets", "observed_at": 2}]
    result = analyze(events)
    assert not result["alerts"]
    assert result["timing_notices"][0]["path_alerts_suppressed_for_batch"] == ["alice", "operator"]


def test_self_approved_grant_is_flagged_even_if_marked_approved():
    events = [{"id": "g1", "actor": "operator", "action": "grant", "service": "frontend", "outcome": "allowed",
               "observed_at": 10, "details": {"owner": "mallory", "target_service": "secrets",
                                               "approved": True, "approved_by": "operator"}},
              {"id": "g2", "actor": "operator", "action": "grant", "service": "frontend", "outcome": "allowed",
               "observed_at": 20, "details": {"owner": "dana", "target_service": "secrets",
                                               "approved": True, "approved_by": "security-officer"}}]
    alerts = analyze(events)["alerts"]
    assert [(a["event_id"], a["rule"]) for a in alerts] == [("g1", "self_approved_grant")]


@pytest.mark.parametrize("seed", [7, 11, 23])
def test_heldout_set_reports_known_misses_honestly(seed):
    events = make_heldout_events(seed)
    report = evaluate(events)
    # Known weak spots are included on purpose: approved-edge insider access, slow lateral
    # movement, first direct use after a self-approved grant, and late use of an approval.
    assert report["malicious_events"] == 46 and report["false_negatives"] == 14
    assert report["false_positives"] == 4 and 0.75 < report["f1"] < 0.8
    names = {e["actor"] for e in events} - {"operator"}
    assert all(name.startswith("u-") for name in names)
    flipped = copy.deepcopy(events)
    for event in flipped:
        event["malicious"] = not event["malicious"]
    assert analyze(events) == analyze(flipped)
