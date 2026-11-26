"""Adapter v1 contract tests. Need only Python 3.12, pqcrypto and pytest."""

import base64
import hashlib
import hmac
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from pqcrypto.kem import ml_kem_768

ROOT = Path(__file__).resolve().parents[1]
ENTRY = ROOT / "track4_service.py"
MARKER = "synthetic-key-material-7f3a"


def call(state, **request):
    env = {k: v for k, v in os.environ.items() if k != "TRACK4_STATE_DIR"}
    env["TRACK4_STATE_DIR"] = str(state)
    done = subprocess.run([sys.executable, "-B", str(ENTRY)], input=json.dumps(request).encode(),
                          capture_output=True, cwd=ROOT, env=env, timeout=20)
    assert MARKER.encode() not in done.stdout and MARKER.encode() not in done.stderr
    return done.returncode, json.loads(done.stdout)


@pytest.fixture
def state(tmp_path):
    code, reply = call(tmp_path, op="setup", owners={"brief": "maya", "plan": "omar", "memo": "dana"},
                       contents={"brief": "demo note", "plan": "peer body", "memo": "disabled body"},
                       disabled=["dana"], key_material=MARKER)
    assert (code, reply) == (0, {"ready": True})
    return tmp_path


def test_read_revoke_audit_round_trip(state):
    assert call(state, op="read", actor="maya", asset="brief", request_id="r01")[1] == {
        "decision": "allow", "body": "demo note"}
    assert call(state, op="read", actor="maya", asset="plan", request_id="r02")[1] == {"decision": "deny"}
    assert call(state, op="read", actor="dana", asset="memo", request_id="r03")[1] == {"decision": "deny"}
    call(state, op="revoke", actor="maya")
    assert call(state, op="read", actor="maya", asset="brief", request_id="r04")[1] == {"decision": "deny"}
    assert call(state, op="read", actor="omar", asset="plan", request_id="r05")[1]["decision"] == "allow"
    for request_id, decision in (("r01", "allow"), ("r02", "deny"), ("r03", "deny"), ("r04", "deny")):
        reply = call(state, op="audit", request_id=request_id)[1]
        assert (reply["request_id"], reply["decision"], reply["recorded"]) == (request_id, decision, True)
    assert call(state, op="audit", request_id="never")[1]["recorded"] is False


def test_request_id_cannot_be_reused_to_rewrite_audit(state):
    call(state, op="read", actor="maya", asset="plan", request_id="r10")
    assert call(state, op="read", actor="maya", asset="brief", request_id="r10")[1] == {"decision": "deny"}
    assert call(state, op="audit", request_id="r10")[1]["decision"] == "deny"


def test_protected_read_proof_verifies_with_recipient_secret(state):
    public_key, secret_key = ml_kem_768.generate_keypair()
    challenge = "fresh-challenge-1"
    code, reply = call(state, op="protected_read", actor="maya", asset="brief", challenge=challenge,
                       public_key=base64.b64encode(public_key).decode())
    assert code == 0 and reply["decision"] == "allow"
    shared = ml_kem_768.decrypt(secret_key, base64.b64decode(reply["ciphertext"]))
    expected = hmac.new(shared, (challenge + "demo note").encode(), hashlib.sha256).hexdigest()
    assert hmac.compare_digest(reply["proof"], expected)
    assert "demo note" not in json.dumps(reply)


@pytest.mark.parametrize("actor,asset,key_bytes", [("omar", "brief", 1184), ("dana", "memo", 1184),
                                                   ("maya", "brief", 32)])
def test_protected_read_denies_without_disclosure(state, actor, asset, key_bytes):
    code, reply = call(state, op="protected_read", actor=actor, asset=asset, challenge="c",
                       public_key=base64.b64encode(os.urandom(key_bytes)).decode())
    assert (code, reply) == (0, {"decision": "deny"})


def test_protected_read_denied_after_revocation(state):
    call(state, op="revoke", actor="maya")
    public_key, _ = ml_kem_768.generate_keypair()
    reply = call(state, op="protected_read", actor="maya", asset="brief", challenge="c",
                 public_key=base64.b64encode(public_key).decode())[1]
    assert reply == {"decision": "deny"}


def test_audit_log_is_signed_and_tamper_evident(state):
    call(state, op="read", actor="maya", asset="brief", request_id="r20")
    assert call(state, op="verify_audit")[1]["verified"] is True
    path = state / "adapter-state.json"
    document = json.loads(path.read_bytes())
    document["audit"][-1]["body"]["decision"] = "deny"
    document["decisions"]["r20"] = "deny"
    path.write_text(json.dumps(document))
    code, reply = call(state, op="verify_audit")
    assert code == 1 and "error" in reply


def test_user_text_cannot_forge_a_second_event(state):
    before = len(json.loads((state / "adapter-state.json").read_bytes())["audit"])
    quoted = 'x","decision":"allow","actor":"omar'
    multiline = 'x"}\n{"op":"read","actor":"omar","decision":"allow'
    call(state, op="read", actor=quoted, asset="plan", request_id="r30")
    call(state, op="read", actor=multiline, asset="plan", request_id="r31")
    document = json.loads((state / "adapter-state.json").read_bytes())
    first, second = (record["body"] for record in document["audit"][before:])
    assert len(document["audit"]) == before + 2
    assert (first["actor"], first["decision"]) == (quoted, "deny")
    # Control characters are rejected outright, so no actor is recorded for that request.
    assert (second["actor"], second["decision"], second["reason"]) == (None, "deny", "malformed request")
    assert call(state, op="verify_audit")[1]["verified"] is True


def test_malformed_requests_fail_closed(state, tmp_path_factory):
    assert call(state, op="read", actor=["maya"], asset="brief", request_id="r40")[1] == {"decision": "deny"}
    code, reply = call(state, op="nope")
    assert code == 1 and reply == {"error": "unknown op"}
    empty = tmp_path_factory.mktemp("empty")
    assert call(empty, op="read", actor="maya", asset="brief", request_id="r1")[1] == {"decision": "deny"}


def test_setup_resets_previous_state(state):
    call(state, op="revoke", actor="maya")
    call(state, op="setup", owners={"brief": "maya"}, contents={"brief": "v2"}, disabled=[], key_material=MARKER)
    assert call(state, op="read", actor="maya", asset="brief", request_id="r50")[1]["body"] == "v2"
