import copy
import os

import pytest
from cryptography.exceptions import InvalidSignature, InvalidTag

from trustverify.crypto import public, sign
from trustverify.protocol import Receiver, SUITE, encrypt, recover_packets
from trustverify.client import Identity


@pytest.fixture
def endpoints(tmp_path):
    alice, bob = Identity.generate("alice-device"), Identity.generate("bob-device")
    receiver = Receiver(tmp_path / "bob", bob.device, 1, bob.key)
    yield alice, bob, receiver
    receiver.close()


def prepare(endpoints, message=b"hello"):
    alice, bob, receiver = endpoints
    offer = receiver.offer(alice.device, 1, public(alice.key))
    manifest, packets = encrypt(alice.key, offer, public(bob.key), message)
    return offer, manifest, packets


def test_reordering_loss_recovery_replay_and_vault_restart(endpoints, tmp_path):
    alice, bob, receiver = endpoints
    message = os.urandom(80000)
    _, manifest, packets = prepare(endpoints, message)
    retrieved = recover_packets(lambda i: packets[i][1], len(packets), drop={0, 2}, reverse=True)
    assert receiver.receive(manifest, retrieved + [retrieved[0]]) == message
    with pytest.raises(ValueError, match="duplicate"):
        receiver.receive(manifest, packets)
    restarted = Receiver(receiver.directory, bob.device, 1, bob.key)
    assert restarted.read(manifest["offer"]["binding"]["session"]) == message
    with pytest.raises(ValueError, match="duplicate"):
        restarted.receive(manifest, packets)
    restarted.close()


def test_recipient_tamper_and_other_identity_cannot_inherit_session(endpoints, tmp_path):
    _, manifest, packets = prepare(endpoints)
    _, bob, receiver = endpoints
    modified = copy.deepcopy(manifest)
    modified["offer"]["binding"]["recipient_device"] = "mallory-device"
    with pytest.raises(ValueError, match="offer changed"):
        receiver.receive(modified, packets)
    mallory = Identity.generate("mallory-device")
    other = Receiver(tmp_path / "mallory", mallory.device, 1, mallory.key)
    with pytest.raises(ValueError, match="unknown"):
        other.receive(manifest, packets)
    other.close()


def test_incomplete_invalid_and_interrupted_sessions_discarded(endpoints):
    _, _, receiver = endpoints
    _, manifest, packets = prepare(endpoints, os.urandom(50000))
    session = manifest["offer"]["binding"]["session"]
    with pytest.raises(ValueError, match="incomplete"):
        receiver.receive(manifest, packets[:-1])
    assert session not in receiver.pending
    with pytest.raises(ValueError, match="recovery exhausted"):
        recover_packets(lambda _: None, 1)
    _, manifest, packets = prepare(endpoints)
    corrupted = [(0, packets[0][1][:-1] + bytes([packets[0][1][-1] ^ 1]))]
    with pytest.raises(ValueError, match="integrity"):
        receiver.receive(manifest, corrupted)


def test_forward_secrecy_identity_key_cannot_decrypt_recording(endpoints):
    alice, bob, receiver = endpoints
    offer, manifest, packets = prepare(endpoints, b"completed session secret")
    ciphertext = b"".join(packet for _, packet in packets)
    assert receiver.receive(manifest, packets) == b"completed session secret"
    assert not receiver.pending
    from trustverify.crypto import canonical
    # A long-term signing key is not the one-use recipient HPKE secret.
    with pytest.raises((TypeError, ValueError)):
        SUITE.decrypt(ciphertext, bob.key, info=canonical(offer["binding"]))
    # Exposing the signing key lets an attacker sign new offers, not recover an old KEM secret.
    from cryptography.hazmat.primitives import hpke
    from cryptography.hazmat.primitives.asymmetric import mlkem, x25519
    attacker_kem = hpke.MLKEM768X25519PrivateKey(
        mlkem.MLKEM768PrivateKey.generate(), x25519.X25519PrivateKey.generate())
    with pytest.raises(InvalidTag):
        SUITE.decrypt(ciphertext, attacker_kem, info=canonical(offer["binding"]))
    assert receiver.read(offer["binding"]["session"]) == b"completed session secret"


def test_sender_signature_required_even_with_valid_encryption(endpoints):
    alice, bob, receiver = endpoints
    offer, manifest, packets = prepare(endpoints)
    attacker = Identity.generate("mallory-device")
    unsigned = {k: v for k, v in manifest.items() if k != "signature"}
    manifest["signature"] = sign(attacker.key, "manifest", unsigned)
    with pytest.raises(InvalidSignature):
        receiver.receive(manifest, packets)
