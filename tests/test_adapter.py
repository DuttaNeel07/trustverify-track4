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
from pqcrypto.sign import ml_dsa_65

ROOT = Path(__file__).resolve().parents[1]
ENTRY = ROOT / "track4_service.py"
MARKER = "synthetic-key-material-7f3a"


def read_log(state):
    return [json.loads(line) for line in (state / "adapter-audit.jsonl").read_bytes().splitlines()]


def write_log(state, records, **changes):
    """Attacker with write access: replace the log and make the state document agree with it."""
    from trustverify.adapter import _record_hash
    from trustverify.encoding import canonical
    data = b"".join(canonical(record) + b"\n" for record in records)
    (state / "adapter-audit.jsonl").write_bytes(data)
    document = json.loads((state / "adapter-state.json").read_bytes())
    document.update(audit_bytes=len(data), seq=len(records), head=_record_hash(records[-1]),
                    setup_record=records[0], **changes)
    (state / "adapter-state.json").write_text(json.dumps(document))


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
    assert code == 0 and reply["ready"] is True and len(reply["audit_key_sha256"]) == 64
    (tmp_path / "pinned.txt").write_text(reply["audit_key_sha256"])
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
    records = read_log(state)
    records[-1]["body"]["decision"] = "deny"
    write_log(state, records)
    code, reply = call(state, op="verify_audit")
    assert code == 1 and "error" in reply


def test_user_text_cannot_forge_a_second_event(state):
    before = len(read_log(state))
    quoted = 'x","decision":"allow","actor":"omar'
    multiline = 'x"}\n{"op":"read","actor":"omar","decision":"allow'
    call(state, op="read", actor=quoted, asset="plan", request_id="r30")
    call(state, op="read", actor=multiline, asset="plan", request_id="r31")
    records = read_log(state)
    first, second = (record["body"] for record in records[before:])
    assert len(records) == before + 2
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


def _resign_with_new_key(state, change):
    """Attacker with write access: edit history, then re-sign it all under a fresh key."""
    from trustverify.adapter import DOMAIN, ZERO, _record_hash
    from trustverify.encoding import b64, canonical
    records = read_log(state)
    public_key, secret_key = ml_dsa_65.generate_keypair()
    previous, decisions = ZERO, {}
    for record in records:
        change(record["body"])
        record["body"]["previous"] = previous
        record["signature"] = b64(ml_dsa_65.sign(secret_key, DOMAIN + canonical(record["body"])))
        previous = _record_hash(record)
        if record["body"].get("request_id"):
            decisions[record["body"]["request_id"]] = record["body"]["decision"]
    write_log(state, records, audit_public=b64(public_key), decisions=decisions)


def test_pinned_fingerprint_detects_a_resigned_log(state):
    call(state, op="read", actor="maya", asset="brief", request_id="r60")
    pinned = (state / "pinned.txt").read_text()
    assert call(state, op="verify_audit", audit_key_sha256=pinned)[1]["anchored"] is True

    def flip(body):
        if body.get("request_id") == "r60":
            body["decision"] = "deny"
    _resign_with_new_key(state, flip)
    # The protected public key rejects substitution even before an operator supplies a pin.
    assert call(state, op="audit", request_id="r60")[0] == 1
    assert call(state, op="verify_audit")[0] == 1
    code, reply = call(state, op="verify_audit", audit_key_sha256=pinned)
    assert code == 1 and "protected public key" in reply["error"]


def test_pinned_checkpoint_detects_rewritten_or_truncated_history(state):
    call(state, op="read", actor="maya", asset="brief", request_id="r70")
    checkpoint = call(state, op="verify_audit")[1]
    pin = {"seq": checkpoint["seq"], "head": checkpoint["head"]}
    call(state, op="read", actor="omar", asset="plan", request_id="r71")
    assert call(state, op="verify_audit", checkpoint=pin)[1]["verified"] is True
    write_log(state, read_log(state)[:1])
    code, reply = call(state, op="verify_audit", checkpoint=pin)
    assert code == 1


def test_tampered_body_is_never_served(state):
    path = state / "adapter-state.json"
    document = json.loads(path.read_bytes())
    document["contents"]["brief"] = "attacker text"
    path.write_text(json.dumps(document))
    assert call(state, op="read", actor="maya", asset="brief", request_id="r80")[1] == {"decision": "deny"}
    public_key, _ = ml_kem_768.generate_keypair()
    assert call(state, op="protected_read", actor="maya", asset="brief", challenge="c",
                public_key=base64.b64encode(public_key).decode())[1] == {"decision": "deny"}


def test_modified_body_and_cached_hash_are_rejected_before_read(state):
    path = state / "adapter-state.json"
    document = json.loads(path.read_bytes())
    document["contents"]["brief"] = "attacker text"
    document["setup_record"]["body"]["contents_sha256"]["brief"] = hashlib.sha256(b"attacker text").hexdigest()
    path.write_text(json.dumps(document))
    public_key, _ = ml_kem_768.generate_keypair()
    for request in [dict(op="read", actor="maya", asset="brief", request_id="changed-hash"),
                    dict(op="protected_read", actor="maya", asset="brief", challenge="c",
                         public_key=base64.b64encode(public_key).decode())]:
        code, reply = call(state, **request)
        assert code == 1 and "setup signature" in reply["error"] and "body" not in reply


def test_legacy_adapter_public_key_is_bound_to_protected_private_key(state):
    public = state / "keys" / "adapter-audit.pub"
    public.unlink()
    assert call(state, op="read", actor="maya", asset="brief", request_id="upgrade")[1]["body"] == "demo note"
    assert public.exists()
    public.unlink()
    _resign_with_new_key(state, lambda body: None)
    code, reply = call(state, op="read", actor="maya", asset="brief", request_id="forged-upgrade")
    assert code == 1 and "protected signing key" in reply["error"]
    assert not public.exists()


def test_crashed_unacknowledged_tail_is_dropped_and_log_stays_valid(state):
    call(state, op="read", actor="maya", asset="brief", request_id="r90")
    with (state / "adapter-audit.jsonl").open("ab") as stream:
        stream.write(b'{"torn": tru')  # a process died mid-append, before saving state
    assert call(state, op="read", actor="omar", asset="plan", request_id="r91")[1]["decision"] == "allow"
    assert call(state, op="verify_audit", audit_key_sha256=(state / "pinned.txt").read_text())[1]["verified"]


def test_state_document_stays_small_as_the_log_grows(state):
    before = (state / "adapter-state.json").stat().st_size
    for n in range(40):
        call(state, op="read", actor="maya", asset="brief", request_id=f"g{n}")
    # Only the request_id -> decision index grows (tens of bytes per request), not the signatures.
    assert (state / "adapter-state.json").stat().st_size - before < 40 * 64
    assert (state / "adapter-audit.jsonl").stat().st_size > 40 * 4000
