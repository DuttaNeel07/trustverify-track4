import pytest

from conftest import client
from trustverify.authority import Denied
from trustverify.watch import Watcher


def unapproved_grant(operator):
    operator.call("remove_permission", owner="alice", service="secrets")
    operator.call("grant", owner="alice", service="secrets")


def approve_again(operator):
    approval = operator.officer.call("approve", owner="alice", service="secrets")["approval"]
    operator.call("grant", owner="alice", service="secrets", approval=approval)


def test_restart_keeps_handled_alerts_and_preserves_reapproved_access(sandbox):
    authority, operator, alice, _ = sandbox
    watcher = Watcher(authority, operator.officer)
    unapproved_grant(operator)
    assert watcher.poll()[0]["response"]["status"] == "applied"
    approve_again(operator)
    restarted = Watcher(authority, operator.officer)
    assert restarted.poll() == []
    assert client(authority, alice, "node-c").call("access")["actor"] == "alice"


def test_first_watch_skips_historical_alert_superseded_by_approved_grant(sandbox):
    authority, operator, alice, _ = sandbox
    unapproved_grant(operator)
    operator.call("remove_permission", owner="alice", service="secrets")
    approve_again(operator)
    watcher = Watcher(authority, operator.officer)
    response = watcher.poll()[0]["response"]
    assert response["status"] == "skipped" and "superseded" in response["reason"]
    assert client(authority, alice, "node-c").call("access")["actor"] == "alice"
    assert watcher.poll() == []


def test_reapproval_between_detection_and_response_is_checked_atomically(sandbox, monkeypatch):
    authority, operator, alice, _ = sandbox
    unapproved_grant(operator)
    original = operator.officer.call

    def race(action, **data):
        if action == "remove_permission":
            approval = original("approve", owner="alice", service="secrets")["approval"]
            operator.call("grant", owner="alice", service="secrets", approval=approval)
        return original(action, **data)

    monkeypatch.setattr(operator.officer, "call", race)
    response = Watcher(authority, operator.officer).poll()[0]["response"]
    assert response["status"] == "skipped"
    assert client(authority, alice, "node-c").call("access")["actor"] == "alice"


def test_alert_only_watcher_does_not_consume_responder_work(sandbox):
    authority, operator, _, _ = sandbox
    unapproved_grant(operator)
    assert Watcher(authority).poll()[0]["response"]["action"] == "none"
    assert Watcher(authority, operator.officer).poll()[0]["response"]["status"] == "applied"


def test_failed_response_is_retried_after_restart(sandbox, monkeypatch):
    authority, operator, alice, _ = sandbox
    unapproved_grant(operator)
    original = operator.officer.call
    attempts = []

    def temporary_failure(action, **data):
        attempts.append(action)
        if len(attempts) == 1:
            raise Denied("temporary responder failure", 503)
        return original(action, **data)

    monkeypatch.setattr(operator.officer, "call", temporary_failure)
    assert Watcher(authority, operator.officer).poll()[0]["response"]["status"] == "failed"
    assert Watcher(authority, operator.officer).poll()[0]["response"]["status"] == "applied"
    with pytest.raises(Denied, match="permission"):
        client(authority, alice, "node-c").call("access")


def test_rollback_reused_sequence_number_is_a_new_alert(sandbox, tmp_path):
    authority, operator, _, _ = sandbox
    backup = tmp_path / "before-alert.backup"
    authority.backup(backup)
    operator.call("grant", owner="alice", service="secrets")
    operator.call("grant", owner="alice", service="secrets")
    watcher = Watcher(authority, operator.officer)
    previous = watcher.poll()
    assert [a["response"]["status"] for a in previous] == ["skipped", "applied"]
    authority.restore(backup, accept_rollback=True)
    operator.call("grant", owner="alice", service="secrets")
    current = Watcher(authority, operator.officer).poll()
    assert len(current) == 1 and current[0]["event_id"] == previous[-1]["event_id"]
    assert current[0]["response"]["status"] == "applied"
