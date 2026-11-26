"""Executable checklist with actual HTTP service processes and fresh synthetic keys."""

import contextlib
import copy
import hashlib
import json
import multiprocessing
import os
import selectors
import subprocess
import sys
import time
from pathlib import Path

from .authority import Authority, Denied, NODES, verify_log
from .client import Client, Identity, Local, Remote
from .crypto import atomic_write, b64, canonical, new_identity, private_bytes, public, unb64
from .detector import analyze, evaluate
from .protocol import Receiver, encrypt, recover_packets


@contextlib.contextmanager
def nodes(authority):
    processes, remotes = [], {}
    try:
        for node in NODES:
            process = subprocess.Popen(
                [sys.executable, "-m", "trustverify", "serve", "--state", str(authority.directory),
                 "--operator", str(authority.operator), "--node", node, "--port", "0"],
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            processes.append(process)
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                if not selector.select(timeout=10):
                    raise RuntimeError(f"{node} did not start within 10 seconds")
            line = process.stdout.readline()
            if not line:
                raise RuntimeError(f"{node} startup failed: {process.stderr.read(2048)}")
            remotes[node] = Remote(json.loads(line)["url"], node)
        yield remotes
    finally:
        for process in processes:
            process.terminate()
        for process in processes:
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
            process.stdout.close()
            process.stderr.close()


def _crash_rotation(directory, operator, identity, new_key, phase):
    def fault(here):
        if here == phase:
            os._exit(77)
    authority = Authority(directory, operator, fault=fault)
    Client(Local(authority), identity, authority.trust).call("rotate", **identity.rotation(new_key))


def expect_denied(callback, phrase=None):
    try:
        callback()
    except (Denied, ValueError) as exc:
        if phrase is not None and phrase not in str(exc):
            raise AssertionError(f"wrong rejection: {exc}") from exc
        return str(exc)
    raise AssertionError("operation unexpectedly succeeded")


def run(directory, fixture_path=None, progress=print):
    directory = Path(directory).resolve()
    directory.mkdir(parents=True, exist_ok=False, mode=0o700)
    started = time.perf_counter()
    admin = Identity.generate("operator-device")
    admin.save(directory / "identities" / "operator")
    authority = Authority.initialize(directory / "authority", directory / "operator", public(admin.key))
    alice, bob, carol = (Identity.generate(name + "-device") for name in ("alice", "bob", "carol"))
    checks, performance = {}, {}
    with nodes(authority) as remotes:
        progress("Three loopback service processes running; fresh ML-DSA credentials generated.")
        operator = Client(remotes["node-a"], admin, authority.trust)
        for owner, identity in (("alice", alice), ("bob", bob), ("carol", carol)):
            identity.save(directory / "identities" / owner)
            operator.call("enroll", **identity.enrollment(owner))
            for service in (NODES.values() if owner != "carol" else ["frontend"]):
                approval = operator.call("approve", owner=owner, service=service)["approval"]
                operator.call("grant", owner=owner, service=service, approval=approval)
        receiver = Receiver(directory / "inbox-bob", bob.device, 1, bob.key)
        try:
            old_alice = Client(remotes["node-a"], alice, authority.trust)
            recipient_public = old_alice.directory(bob.device)["public"]
            sender_public = Client(remotes["node-b"], bob, authority.trust).directory(alice.device)["public"]
            offer = receiver.offer(alice.device, 1, sender_public)
            plaintext = os.urandom(96 * 1024)
            encrypt_start = time.perf_counter()
            manifest, packets = encrypt(alice.key, offer, recipient_public, plaintext)
            performance["endpoint_encrypt_and_sign_ms"] = (time.perf_counter() - encrypt_start) * 1000
            performance["plaintext_bytes"] = len(plaintext)
            performance["ciphertext_bytes"] = manifest["ciphertext_bytes"]
            performance["signed_manifest_bytes"] = len(canonical(manifest))
            transfer = old_alice.call("start", manifest=manifest)["transfer"]
            old_alice.call("put_chunk", transfer=transfer, index=0, body=b64(packets[0][1]))
            replacement = new_identity()
            atomic_write(directory / "identities" / "alice" / "v2.pem", private_bytes(replacement))
            old_alice.call("rotate", **alice.rotation(replacement))
            alice2 = Identity(alice.device, replacement, 2)
            alice2.save(directory / "identities" / "alice")
            checks["rotation_old_key_rejected_all_nodes"] = {
                node: expect_denied(lambda api=api: Client(api, alice, authority.trust).call("access"), "retired")
                for node, api in remotes.items()}
            for node, api in remotes.items():
                assert Client(api, alice2, authority.trust).call("access")["actor"] == "alice"
            for index, data in packets[1:]:
                api = remotes[list(NODES)[index % 3]]
                Client(api, alice, authority.trust).call("put_chunk", transfer=transfer, index=index, body=b64(data))
            old_alice.call("finish", transfer=transfer)
            bob_client = Client(remotes["node-b"], bob, authority.trust)
            downloaded = bob_client.call("fetch", transfer=transfer)

            def fetch(index):
                api = remotes[list(NODES)[index % 3]]
                return unb64(Client(api, bob, authority.trust).call("read_chunk", transfer=transfer, index=index)["body"])

            incoming = recover_packets(fetch, manifest["chunks"], drop={0, 2}, reverse=True)
            decrypt_start = time.perf_counter()
            assert receiver.receive(downloaded, incoming) == plaintext
            performance["hpke_receive_and_vault_commit_ms"] = (time.perf_counter() - decrypt_start) * 1000
            checks["rotation_transfer_continues"] = True
            checks["loss_and_reordering_recovered"] = True
            checks["completed_message_sha256"] = hashlib.sha256(plaintext).hexdigest()
            checks["duplicate_message_rejected"] = expect_denied(lambda: receiver.receive(downloaded, incoming), "duplicate")
            assert not receiver.pending
            checks["completed_ephemeral_session_discarded"] = True

            tamper_offer = receiver.offer(alice2.device, 2, public(alice2.key))
            tamper_manifest, tamper_packets = encrypt(alice2.key, tamper_offer, public(bob.key), b"recipient binding test")
            modified = copy.deepcopy(tamper_manifest)
            modified["offer"]["binding"]["recipient_device"] = "carol-device"
            checks["recipient_tamper_rejected"] = expect_denied(lambda: receiver.receive(modified, tamper_packets), "changed")

            incomplete_offer = receiver.offer(alice2.device, 2, public(alice2.key))
            incomplete_manifest, _ = encrypt(alice2.key, incomplete_offer, public(bob.key), b"must not deliver")
            checks["incomplete_delivery_rejected"] = expect_denied(lambda: receiver.receive(incomplete_manifest, []), "incomplete")

            progress("Encrypted transfer survived rotation, fragment loss and reordering; duplicate/tampered messages rejected.")
            began = time.perf_counter()
            operator.call("revoke", device=alice2.device)
            committed = time.perf_counter()
            enforced = {}
            for node, api in remotes.items():
                expect_denied(lambda api=api: Client(api, alice2, authority.trust).call("access"), "revoked")
                last_observed = time.perf_counter()
                enforced[node] = (last_observed - committed) * 1000
                assert Client(api, bob, authority.trust).call("access")["actor"] == "bob"
            performance["revocation_commit_roundtrip_ms"] = (committed - began) * 1000
            performance["revocation_ack_to_node_observed_rejection_ms"] = enforced
            performance["revocation_ack_to_last_observed_rejection_ms"] = max(enforced.values())
            performance["revocation_request_to_last_observed_rejection_ms"] = (last_observed - began) * 1000
            performance["revocation_measurement"] = "one harness monotonic clock; sequential probes; observation upper bounds, not replication latency"
            checks["revocation_all_nodes_and_other_user_access"] = True
            reenrolled = Identity.generate("alice-replacement")
            operator.call("enroll", **reenrolled.enrollment("alice"))
            reenrolled.save(directory / "identities" / "alice-replacement")
            current_alice = Client(remotes["node-a"], reenrolled, authority.trust)
            assert current_alice.call("access")["actor"] == "alice"
            checks["owner_reenrollment"] = True

            # Real crashes exercise SQLite rollback and recovery of a committed, uncheckpointed tail.
            new_bob_key = new_identity()
            atomic_write(directory / "identities" / "bob" / "v2.pem", private_bytes(new_bob_key))
            for phase, expected in (("rotation_staged", 1), ("rotation_committed", 2)):
                child = multiprocessing.get_context("fork").Process(target=_crash_rotation,
                    args=(authority.directory, authority.operator, bob, new_bob_key, phase))
                child.start()
                child.join(10)
                if child.is_alive():
                    child.kill()
                    child.join()
                    raise RuntimeError("fault-injection process timed out")
                assert child.exitcode == 77
                authority.recover()
                assert authority.directory_entry(bob.device)["entry"]["version"] == expected
                checks[phase + "_recovery"] = expected
            bob2 = Identity(bob.device, new_bob_key, 2)
            bob2.save(directory / "identities" / "bob")
            assert Client(remotes["node-c"], bob2, authority.trust).call("access")["actor"] == "bob"
            assert receiver.read(transfer) == plaintext
            expect_denied(lambda: Client(remotes["node-a"], alice2, authority.trust).call("access"), "revoked")
            checks["crash_preserves_revocation_and_protected_data"] = True

            current_alice.call("access", note='hello\n{"actor":"operator","action":"grant"}')
            event = authority.export_log()["records"][-1]["body"]
            assert event["actor"] == "alice" and event["action"] == "access"
            checks["log_injection_keeps_actor_and_boundary"] = True
            request = current_alice.envelope("access", {})
            current_alice.api.request(request)
            checks["signed_request_replay_rejected"] = expect_denied(lambda: current_alice.api.request(request), "replayed")

            operator.call("grant", owner="carol", service="secrets")
            Client(remotes["node-a"], carol, authority.trust).call("access")
            # Distinct authority timestamps establish a definite observed transition.
            Client(remotes["node-c"], carol, authority.trust).call("access")
            exported = authority.export_log()
            verify_log(exported["records"], authority.trust, exported["checkpoint"])
            detection = analyze([r["body"] for r in exported["records"]])
            assert any(a["rule"] == "unapproved_privilege_grant" and a["identity"] == "carol" for a in detection["alerts"])
            assert any(a["rule"] == "unexpected_service_transition" and a["identity"] == "carol" for a in detection["alerts"])
            checks["verified_real_log_detection"] = True
            atomic_write(directory / "audit-export.json", canonical(exported))
            atomic_write(directory / "alerts.json", canonical(detection))

            backup = directory / "keys.backup"
            authority.backup(backup)
            damaged = bytearray(backup.read_bytes())
            damaged[len(damaged) // 2] ^= 1
            atomic_write(directory / "corrupt.backup", damaged)
            checks["corrupt_backup_rejected"] = expect_denied(lambda: authority.restore(directory / "corrupt.backup"), "verification failed")
            assert authority.restore(backup)["restored"]
            checks["verified_backup_restored"] = True
            authority.recover()
            progress("Both crash boundaries recovered; revocation stayed enforced; corrupted backup rejected; signed logs verified.")
        finally:
            receiver.close()
    performance["demo_wall_seconds"] = time.perf_counter() - started
    report = {"checks": checks, "performance": performance, "limits": {
        "new_request_rotation_grace_seconds": 0, "admitted_transfer_grant_seconds": 120,
        "session_resumption": "unsupported; fresh handshake after interruption",
        "topology": "three HTTP enforcement processes; one shared transactional SQLite authority",
        "scope": "loopback, synthetic identities, no production security claim"}}
    if fixture_path:
        report["detector_evaluation"] = evaluate(json.loads(Path(fixture_path).read_bytes()))
    atomic_write(directory / "report.json", canonical(report))
    progress(f"Evidence: {directory / 'report.json'}")
    return report
