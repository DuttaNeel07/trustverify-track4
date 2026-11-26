"""One-use, signed recipient offers around the library's hybrid HPKE.

This application protocol is a sandbox prototype, not Signal or Noise.
"""

import hashlib
import math
import os
import sqlite3
import uuid
from pathlib import Path

from cryptography.hazmat.primitives import hpke
from cryptography.hazmat.primitives.asymmetric import mlkem, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .crypto import SUITE, b64, canonical, sign, unb64, verify

PROTOCOL = "trustverify/hpke-xwing/v1"
CHUNK_SIZE = 16 * 1024
MAX_PLAINTEXT = 1024 * 1024
MAX_CIPHERTEXT = MAX_PLAINTEXT + 2048
MAX_CHUNKS = math.ceil(MAX_CIPHERTEXT / CHUNK_SIZE)


def validate_manifest(manifest, sender_public, recipient_public):
    if set(manifest) != {"offer", "chunks", "ciphertext_bytes", "ciphertext_hash", "signature"}:
        raise ValueError("invalid manifest fields")
    offer = manifest["offer"]
    if set(offer) != {"binding", "signature"}:
        raise ValueError("invalid offer fields")
    binding = offer["binding"]
    if set(binding) != {"protocol", "session", "sender_device", "sender_version",
                        "recipient_device", "recipient_version", "kem_mlkem", "kem_x25519"}:
        raise ValueError("invalid binding fields")
    if binding["protocol"] != PROTOCOL or len(binding["session"]) != 32:
        raise ValueError("invalid protocol or session")
    uuid.UUID(hex=binding["session"])
    if type(manifest["chunks"]) is not int or not 1 <= manifest["chunks"] <= MAX_CHUNKS:
        raise ValueError("invalid chunk count")
    size = manifest["ciphertext_bytes"]
    if type(size) is not int or not 1136 <= size <= MAX_CIPHERTEXT:
        raise ValueError("invalid ciphertext size")
    if manifest["chunks"] != math.ceil(size / CHUNK_SIZE):
        raise ValueError("inconsistent chunk count")
    if len(bytes.fromhex(manifest["ciphertext_hash"])) != 32:
        raise ValueError("invalid ciphertext hash")
    verify(recipient_public, "offer", binding, offer["signature"])
    verify(sender_public, "manifest", {k: v for k, v in manifest.items() if k != "signature"},
           manifest["signature"])
    return binding


def encrypt(sender_key, offer, recipient_public, plaintext):
    if not isinstance(plaintext, bytes) or len(plaintext) > MAX_PLAINTEXT:
        raise ValueError("message must be bytes, at most 1 MiB")
    binding = offer["binding"]
    if binding["protocol"] != PROTOCOL:
        raise ValueError("unsupported protocol")
    verify(recipient_public, "offer", binding, offer["signature"])
    recipient = hpke.MLKEM768X25519PublicKey(
        mlkem.MLKEM768PublicKey.from_public_bytes(unb64(binding["kem_mlkem"])),
        x25519.X25519PublicKey.from_public_bytes(unb64(binding["kem_x25519"])))
    ciphertext = SUITE.encrypt(plaintext, recipient, info=canonical(binding))
    chunks = [ciphertext[i:i + CHUNK_SIZE] for i in range(0, len(ciphertext), CHUNK_SIZE)]
    manifest = {"offer": offer, "chunks": len(chunks), "ciphertext_bytes": len(ciphertext),
                "ciphertext_hash": hashlib.sha256(ciphertext).hexdigest()}
    manifest["signature"] = sign(sender_key, "manifest", manifest)
    return manifest, list(enumerate(chunks))


class Receiver:
    """Pending ephemeral keys live only in memory; completed deliveries in a local vault."""

    def __init__(self, directory, device, version, identity_key):
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.device, self.version, self.identity_key = device, version, identity_key
        self.pending = {}
        key_path = self.directory / "vault.key"
        if not key_path.exists():
            # Exclusive creation prevents two receiver processes silently replacing the vault key.
            fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as stream:
                stream.write(os.urandom(32))
                stream.flush()
                os.fsync(stream.fileno())
        self.vault_key = key_path.read_bytes()
        self.db = sqlite3.connect(self.directory / "inbox.sqlite")
        os.chmod(self.directory / "inbox.sqlite", 0o600)
        self.db.execute("CREATE TABLE IF NOT EXISTS deliveries (session TEXT PRIMARY KEY, ciphertext BLOB NOT NULL)")
        self.db.commit()

    def offer(self, sender_device, sender_version, sender_public):
        if len(self.pending) >= 64:
            raise ValueError("too many pending sessions")
        kem = mlkem.MLKEM768PrivateKey.generate()
        dh = x25519.X25519PrivateKey.generate()
        binding = {"protocol": PROTOCOL, "session": uuid.uuid4().hex,
                   "sender_device": sender_device, "sender_version": sender_version,
                   "recipient_device": self.device, "recipient_version": self.version,
                   "kem_mlkem": b64(kem.public_key().public_bytes_raw()),
                   "kem_x25519": b64(dh.public_key().public_bytes_raw())}
        offer = {"binding": binding, "signature": sign(self.identity_key, "offer", binding)}
        self.pending[binding["session"]] = (
            hpke.MLKEM768X25519PrivateKey(kem, dh), canonical(offer), sender_public)
        return offer

    def receive(self, manifest, packets):
        session = manifest["offer"]["binding"]["session"]
        if self.db.execute("SELECT 1 FROM deliveries WHERE session=?", (session,)).fetchone():
            raise ValueError("duplicate completed message")
        if session not in self.pending:
            raise ValueError("unknown or interrupted session; fresh handshake required")
        secret, offered, sender_public = self.pending[session]
        try:
            if canonical(manifest["offer"]) != offered:
                raise ValueError("recipient offer changed")
            from .crypto import public
            binding = validate_manifest(manifest, sender_public, public(self.identity_key))
            chunks = {}
            for count, (index, data) in enumerate(packets, 1):
                if count > MAX_CHUNKS * 4:
                    raise ValueError("too many fragments")
                if type(index) is not int or not 0 <= index < manifest["chunks"]:
                    raise ValueError("invalid fragment index")
                if not isinstance(data, bytes) or len(data) > CHUNK_SIZE:
                    raise ValueError("invalid fragment size")
                if index in chunks and chunks[index] != data:
                    raise ValueError("conflicting duplicate fragment")
                chunks[index] = data
            if len(chunks) != manifest["chunks"]:
                raise ValueError("delivery failed: incomplete message")
            ciphertext = b"".join(chunks[i] for i in range(manifest["chunks"]))
            if len(ciphertext) != manifest["ciphertext_bytes"] or hashlib.sha256(ciphertext).hexdigest() != manifest["ciphertext_hash"]:
                raise ValueError("delivery failed: ciphertext integrity")
            plaintext = SUITE.decrypt(ciphertext, secret, info=canonical(binding))
            nonce = os.urandom(12)
            stored = nonce + AESGCM(self.vault_key).encrypt(nonce, plaintext, session.encode("ascii"))
            with self.db:
                self.db.execute("INSERT INTO deliveries VALUES (?,?)", (session, stored))
            return plaintext
        finally:
            # Python drops references; reliable memory zeroization is not a Python guarantee.
            self.pending.pop(session, None)

    def read(self, session):
        row = self.db.execute("SELECT ciphertext FROM deliveries WHERE session=?", (session,)).fetchone()
        if not row:
            raise ValueError("no completed delivery")
        ciphertext = row[0]
        return AESGCM(self.vault_key).decrypt(ciphertext[:12], ciphertext[12:], session.encode("ascii"))

    def close(self):
        self.pending.clear()
        self.db.close()


def recover_packets(fetch, total, *, drop=(), reverse=False, retries=2):
    """Bounded synthetic transport: fetch missing fragments again before delivery."""
    if type(total) is not int or not 1 <= total <= MAX_CHUNKS or not 0 <= retries <= 3:
        raise ValueError("invalid transport bounds")
    packets = {}
    for attempt in range(retries + 1):
        for index in range(total):
            if index in packets or (attempt == 0 and index in drop):
                continue
            data = fetch(index)
            if data is not None:
                packets[index] = data
        if len(packets) == total:
            break
    if len(packets) != total:
        raise ValueError("delivery failed: recovery exhausted")
    return sorted(packets.items(), reverse=reverse)
