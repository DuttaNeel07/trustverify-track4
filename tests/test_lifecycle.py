import contextlib
import copy
import json
import multiprocessing
import os
import time

import pytest
from cryptography.exceptions import InvalidSignature

from trustverify.authority import Authority, Denied, NODES, connect, verify_log
from trustverify.client import Identity
from trustverify.crypto import new_identity, public, sign
from trustverify.protocol import Receiver, encrypt
from conftest import client


def test_normal_identity_permission_and_signed_request_replay(sandbox):
    authority, operator, alice, _ = sandbox
    alice_client = client(authority, alice)
    request = alice_client.envelope("access", {"note": "hello"})
    assert alice_client.api.request(request)["actor"] == "alice"
    with pytest.raises(Denied, match="replayed"):
        alice_client.api.request(request)
    altered = alice_client.envelope("access", {})
    altered["device"] = "operator-device"
    with pytest.raises(Denied):
        alice_client.api.request(altered)
    with pytest.raises(Denied, match="administrator"):
        alice_client.call("grant", owner="alice", service="secrets")
    operator.call("remove_permission", owner="alice", service="billing")
    with pytest.raises(Denied, match="permission"):
        client(authority, alice, "node-b").call("access")


def test_rotation_cutoff_all_nodes_and_transfer_continuity(sandbox, tmp_path):
    authority, _, alice, bob = sandbox
    receiver = Receiver(tmp_path / "receiver", bob.device, bob.version, bob.key)
    offer = receiver.offer(alice.device, alice.version, public(alice.key))
    message = os.urandom(50000)
    manifest, packets = encrypt(alice.key, offer, public(bob.key), message)
    old = client(authority, alice)
    pre_cutoff_requests = {node: client(authority, alice, node).envelope("access", {}) for node in NODES}
    transfer = old.call("start", manifest=manifest)["transfer"]
    first_index, first_data = packets[0]
    from trustverify.crypto import b64, unb64
    old.call("put_chunk", transfer=transfer, index=first_index, body=b64(first_data))
    replacement = new_identity()
    result = old.call("rotate", **alice.rotation(replacement))
    assert result["version"] == 2 and result["new_request_grace_seconds"] == 0
    for node in NODES:
        with pytest.raises(Denied, match="retired"):
            client(authority, alice, node).api.request(pre_cutoff_requests[node])
        with pytest.raises(Denied, match="retired"):
            client(authority, alice, node).call("access")
        assert client(authority, Identity(alice.device, replacement, 2), node).call("access")["actor"] == "alice"
    for index, data in packets[1:]:
        old.call("put_chunk", transfer=transfer, index=index, body=b64(data))
    old.call("finish", transfer=transfer)
    bob_client = client(authority, bob, "node-c")
    downloaded = bob_client.call("fetch", transfer=transfer)
    incoming = [(i, unb64(bob_client.call("read_chunk", transfer=transfer, index=i)["body"])) for i in reversed(range(manifest["chunks"]))]
    assert receiver.receive(downloaded, incoming) == message
    assert receiver.read(transfer) == message
    receiver.close()


def test_revocation_every_node_reenrollment_and_other_user_access(sandbox):
    authority, operator, alice, bob = sandbox
    started = time.perf_counter()
    operator.call("revoke", device=alice.device)
    latencies = []
    for node in NODES:
        with pytest.raises(Denied, match="revoked"):
            client(authority, alice, node).call("access")
        latencies.append(time.perf_counter() - started)
        assert client(authority, bob, node).call("access")["actor"] == "bob"
    assert len(latencies) == 3 and max(latencies) >= min(latencies)
    replacement = Identity.generate("alice-replacement")
    operator.call("enroll", **replacement.enrollment("alice"))
    assert client(authority, replacement).call("access")["actor"] == "alice"
    with pytest.raises(Denied):
        operator.call("enroll", **Identity.generate(alice.device).enrollment("alice"))
    authority.recover()
    with pytest.raises(Denied, match="revoked"):
        client(authority, alice).call("access")


def test_revocation_overrides_existing_transfer(sandbox, tmp_path):
    authority, operator, alice, bob = sandbox
    receiver = Receiver(tmp_path / "receiver", bob.device, 1, bob.key)
    manifest, packets = encrypt(alice.key, receiver.offer(alice.device, 1, public(alice.key)), public(bob.key), b"secret")
    sender = client(authority, alice)
    transfer = sender.call("start", manifest=manifest)["transfer"]
    operator.call("revoke", device=bob.device)
    from trustverify.crypto import b64
    with pytest.raises(Denied, match="peer revoked"):
        sender.call("put_chunk", transfer=transfer, index=0, body=b64(packets[0][1]))
    receiver.close()


def crash_rotate(directory, operator, identity, replacement, phase):
    def crash(here):
        if here == phase:
            os._exit(77)
    authority = Authority(directory, operator, fault=crash)
    client(authority, identity).call("rotate", **identity.rotation(replacement))


@pytest.mark.parametrize("phase,version", [("rotation_staged", 1), ("rotation_committed", 2)])
def test_real_process_crash_rotation(sandbox, phase, version, tmp_path):
    authority, operator, alice, bob = sandbox
    operator.call("revoke", device=bob.device)
    replacement = new_identity()
    # Fork inherits synthetic key objects without writing additional plaintext key fixtures.
    process = multiprocessing.get_context("fork").Process(
        target=crash_rotate, args=(authority.directory, authority.operator, alice, replacement, phase))
    process.start()
    process.join(10)
    assert not process.is_alive() and process.exitcode == 77
    recovered = Authority(authority.directory, authority.operator)
    recovered.recover()
    entry = recovered.directory_entry(alice.device)["entry"]
    assert entry["version"] == version
    expected = alice if version == 1 else Identity(alice.device, replacement, 2)
    assert client(recovered, expected).call("access")["actor"] == "alice"
    with pytest.raises(Denied, match="revoked"):
        client(recovered, bob).call("access")


def test_backup_corruption_fresh_restore_and_stale_rollback(sandbox, tmp_path):
    authority, operator, alice, _ = sandbox
    backup = tmp_path / "keys.backup"
    authority.backup(backup)
    original = backup.read_bytes()
    damaged = bytearray(original)
    damaged[len(damaged) // 2] ^= 1
    backup.write_bytes(damaged)
    before = authority.export_log()["checkpoint"]
    with pytest.raises(ValueError, match="backup verification failed"):
        authority.restore(backup)
    assert authority.export_log()["checkpoint"] == before
    backup.write_bytes(original)
    assert authority.restore(backup)["restored"]
    authority.recover()
    operator.call("revoke", device=alice.device)
    with pytest.raises(ValueError, match="backup verification failed"):
        authority.restore(backup)
    with pytest.raises(Denied, match="revoked"):
        client(authority, alice).call("access")


def test_injection_actor_integrity_and_public_log_verification(sandbox):
    authority, _, alice, _ = sandbox
    payload = 'hello\n{"actor":"operator","action":"grant"}\r\n\x1b[31m'
    client(authority, alice).call("access", note=payload)
    exported = authority.export_log()
    records = exported["records"]
    event = records[-1]["body"]
    assert event["actor"] == "alice" and event["action"] == "access"
    assert event["details"]["note"] == payload
    assert len(json.dumps(event).splitlines()) == 1
    assert verify_log(records, authority.trust, exported["checkpoint"])["seq"] == len(records)
    tampered = copy.deepcopy(records)
    tampered[-1]["body"]["actor"] = "operator"
    with pytest.raises(InvalidSignature):
        verify_log(tampered, authority.trust, exported["checkpoint"])
    with pytest.raises(ValueError, match="truncated"):
        verify_log(records[:-1], authority.trust, exported["checkpoint"])
    with pytest.raises(ValueError):
        verify_log(records[:2] + records[3:], authority.trust, exported["checkpoint"])


def test_state_tampering_fails_closed(sandbox):
    authority, _, alice, _ = sandbox
    with contextlib.closing(connect(authority.path)) as db:
        with db:
            db.execute("UPDATE users SET role='admin' WHERE id='alice'")
    with pytest.raises(ValueError, match="state integrity"):
        client(authority, alice).call("access")


def test_approval_is_scoped_single_use_and_trusted(sandbox):
    authority, operator, _, _ = sandbox
    approval = operator.officer.call("approve", owner="alice", service="secrets")["approval"]
    with pytest.raises(Denied, match="approval"):
        operator.call("grant", owner="bob", service="secrets", approval=approval)
    assert operator.call("grant", owner="alice", service="secrets", approval=approval)["approved"]
    with pytest.raises(Denied, match="approval"):
        operator.call("grant", owner="alice", service="secrets", approval=approval)


def test_backup_restores_missing_authority_key_and_database(sandbox, tmp_path):
    import shutil
    authority, _, alice, _ = sandbox
    backup = tmp_path / "complete.backup"
    authority.backup(backup)
    shutil.rmtree(authority.directory)
    recovery = Authority(authority.directory, authority.operator, recovery_only=True)
    recovery.restore(backup)
    recovery.recover()
    assert client(recovery, alice).call("access")["actor"] == "alice"


def test_rotation_grant_expires_and_permissions_rechecked(sandbox, tmp_path):
    authority, operator, alice, bob = sandbox
    receiver = Receiver(tmp_path / "receiver", bob.device, 1, bob.key)
    manifest, packets = encrypt(alice.key, receiver.offer(alice.device, 1, public(alice.key)), public(bob.key), b"protected")
    sender = client(authority, alice)
    transfer = sender.call("start", manifest=manifest)["transfer"]
    sender.call("rotate", **alice.rotation(new_identity()))
    from trustverify.crypto import b64
    operator.call("remove_permission", owner="bob", service="frontend")
    with pytest.raises(Denied, match="permission"):
        sender.call("put_chunk", transfer=transfer, index=0, body=b64(packets[0][1]))
    authority.now = lambda: time.time() + 121
    with pytest.raises(Denied, match="grant expired"):
        sender.call("put_chunk", transfer=transfer, index=0, body=b64(packets[0][1]))
    receiver.close()


def test_key_reuse_cannot_bypass_rotation_or_device_revocation(sandbox):
    authority, operator, alice, _ = sandbox
    with pytest.raises(Denied, match="fresh material"):
        client(authority, alice).call("rotate", **alice.rotation(alice.key))
    operator.call("revoke", device=alice.device)
    with pytest.raises(Denied, match="fresh device key"):
        operator.call("enroll", **Identity("alice-replacement", alice.key).enrollment("alice"))


def test_two_person_rule_blocks_self_approved_grants(sandbox):
    authority, operator, _, _ = sandbox
    own = operator.call("approve", owner="alice", service="secrets")["approval"]
    with pytest.raises(Denied, match="two-person"):
        operator.call("grant", owner="alice", service="secrets", approval=own)
    with pytest.raises(Denied, match="two-person"):
        operator.officer.call("approve", owner="security-officer", service="billing")
    records = authority.export_log()["records"]
    denied = [r["body"] for r in records if r["body"]["action"] == "grant" and r["body"]["outcome"] == "denied"]
    assert denied and "two-person" in denied[-1]["details"]["reason"]
    # The same approval still works when the other administrator performs the grant.
    result = operator.officer.call("grant", owner="alice", service="secrets", approval=own)
    assert result["approved"] is True
    grant = authority.export_log()["records"][-1]["body"]
    assert grant["details"]["approved_by"] == "operator" and grant["actor"] == "security-officer"


def test_unauthenticated_requests_do_not_flood_signed_log(sandbox):
    authority, _, alice, _ = sandbox
    before = len(authority.export_log()["records"])
    junk = {"node": "node-a", "device": "nobody", "version": 1, "nonce": "x",
            "action": "access", "data": {}, "signature": "AA=="}
    for _ in range(250):
        with pytest.raises(Denied):
            authority.execute("node-a", dict(junk))
    records = authority.export_log()["records"]
    summaries = [r["body"] for r in records[before:] if r["body"]["action"] == "unauthenticated_rejections"]
    assert len(records) - before == len(summaries) <= 3
    assert sum(s["details"]["count"] for s in summaries) + authority.pending_rejections() == 250
    assert client(authority, alice).call("access")["actor"] == "alice"
    exported = authority.export_log()
    verify_log(exported["records"], authority.trust, exported["checkpoint"])


def test_older_backup_restores_only_with_explicit_rollback_and_keeps_revocations(sandbox, tmp_path):
    authority, operator, alice, bob = sandbox
    backup = tmp_path / "older.backup"
    authority.backup(backup)
    client(authority, bob).call("access", note="after backup")
    operator.call("revoke", device=alice.device)
    with pytest.raises(ValueError, match="verification failed") as refused:
        authority.restore(backup)
    assert "accept_rollback" in str(refused.value.__cause__)
    result = authority.restore(backup, accept_rollback=True)
    assert result["rollback"]["to_seq"] < result["rollback"]["from_seq"]
    assert result["reapplied_revocations"] == [alice.device]
    authority.recover()
    for node in NODES:
        with pytest.raises(Denied, match="revoked"):
            client(authority, alice, node).call("access")
        assert client(authority, bob, node).call("access")["actor"] == "bob"
    restore_event = [r["body"] for r in authority.export_log()["records"] if r["body"]["action"] == "restore"][-1]
    assert restore_event["details"]["reapplied_revocations"] == [alice.device]
    exported = authority.export_log()
    verify_log(exported["records"], authority.trust, exported["checkpoint"])


def test_backup_from_unknown_history_is_rejected(sandbox, tmp_path):
    authority, _, _, bob = sandbox
    backup = tmp_path / "b.backup"
    authority.backup(backup)
    client(authority, bob).call("access")
    (authority.operator / "checkpoints.jsonl").write_bytes(b"")
    with pytest.raises(ValueError, match="verification failed") as refused:
        authority.restore(backup, accept_rollback=True)
    assert "retained signed checkpoint" in str(refused.value.__cause__)


@pytest.mark.parametrize("legacy", [False, True])
def test_rollback_cannot_reactivate_a_retired_key(sandbox, tmp_path, legacy):
    authority, _, alice, _ = sandbox
    backup = tmp_path / "before-rotation.backup"
    authority.backup(backup)
    replacement = new_identity()
    client(authority, alice).call("rotate", **alice.rotation(replacement))
    before = authority.export_log()["checkpoint"]
    if legacy:
        # Older installations have no independently retained rotation floors yet.
        (authority.operator / "revocations.json").unlink()
    with pytest.raises(ValueError, match="verification failed") as refused:
        authority.restore(backup, accept_rollback=True)
    assert "committed key rotation" in str(refused.value.__cause__)
    assert authority.export_log()["checkpoint"] == before
    authority.recover()
    for node in NODES:
        with pytest.raises(Denied, match="retired"):
            client(authority, alice, node).call("access")
        current = Identity(alice.device, replacement, 2)
        assert client(authority, current, node).call("access")["actor"] == "alice"


def crash_restore(directory, operator, backup, phase):
    def crash(here):
        if here == phase:
            os._exit(77)
    Authority(directory, operator, fault=crash).restore(backup, accept_rollback=True)


@pytest.mark.parametrize("phase", ["restore_prepared", "restore_replaced", "checkpoint_published", "restore_checkpointed"])
def test_real_process_crash_during_rollback(sandbox, tmp_path, phase):
    authority, operator, alice, bob = sandbox
    backup = tmp_path / "rollback.backup"
    authority.backup(backup)
    operator.call("revoke", device=alice.device)
    client(authority, bob).call("access")
    process = multiprocessing.get_context("fork").Process(
        target=crash_restore, args=(authority.directory, authority.operator, backup, phase))
    process.start()
    process.join(10)
    assert not process.is_alive() and process.exitcode == 77
    recovered = Authority(authority.directory, authority.operator)
    recovered.recover()
    assert json.loads((authority.operator / "restore-intent.json").read_bytes()) is None
    # A crash before replacement retains the live history; later crashes finish the signed restore.
    records = recovered.export_log()["records"]
    assert any(r["body"]["action"] == "restore" for r in records) == (phase != "restore_prepared")
    with contextlib.closing(connect(recovered.path)) as db:
        head = recovered._head(db)
    assert any(c["head"] == head for c in recovered._historical_checkpoints())
    for node in NODES:
        with pytest.raises(Denied, match="revoked"):
            client(recovered, alice, node).call("access")
        assert client(recovered, bob, node).call("access")["actor"] == "bob"
    exported = recovered.export_log()
    verify_log(exported["records"], recovered.trust, exported["checkpoint"])


def test_forged_restore_intent_is_rejected(sandbox, tmp_path):
    authority, operator, alice, _ = sandbox
    backup = tmp_path / "rollback.backup"
    authority.backup(backup)
    operator.call("revoke", device=alice.device)
    process = multiprocessing.get_context("fork").Process(
        target=crash_restore, args=(authority.directory, authority.operator, backup, "restore_replaced"))
    process.start()
    process.join(10)
    assert not process.is_alive() and process.exitcode == 77
    path = authority.operator / "restore-intent.json"
    intent = json.loads(path.read_bytes())
    intent["body"]["checkpoint"]["head"]["hash"] = "0" * 64
    path.write_text(json.dumps(intent))
    with pytest.raises(InvalidSignature):
        Authority(authority.directory, authority.operator).recover()
