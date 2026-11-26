"""Library primitives only: ML-DSA-65, hybrid HPKE and AES-256-GCM."""

import base64
import json
import os
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives import hpke, serialization
from cryptography.hazmat.primitives.asymmetric import mldsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

SUITE = hpke.Suite(hpke.KEM.MLKEM768_X25519, hpke.KDF.HKDF_SHA256,
                   hpke.AEAD.AES_256_GCM)
DOMAIN = b"trustverify/v1/"


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def b64(value):
    return base64.b64encode(value).decode("ascii")


def unb64(value):
    if not isinstance(value, str):
        raise ValueError("expected base64 text")
    decoded = base64.b64decode(value, validate=True)
    if b64(decoded) != value:
        raise ValueError("noncanonical base64 encoding")
    return decoded


def new_identity():
    return mldsa.MLDSA65PrivateKey.generate()


def public(key):
    return b64(key.public_key().public_bytes_raw())


def sign(key, purpose, value):
    return b64(key.sign(DOMAIN + purpose.encode("ascii") + b"\x00" + canonical(value)))


def verify(public_key, purpose, value, signature):
    mldsa.MLDSA65PublicKey.from_public_bytes(unb64(public_key)).verify(
        unb64(signature), DOMAIN + purpose.encode("ascii") + b"\x00" + canonical(value))


def private_bytes(key):
    return key.private_bytes(serialization.Encoding.PEM,
                             serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())


def load_private(data):
    key = serialization.load_pem_private_key(data, password=None)
    if not isinstance(key, mldsa.MLDSA65PrivateKey):
        raise ValueError("expected ML-DSA-65 private key")
    return key


def atomic_write(path, data, mode=0o600):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, name = tempfile.mkstemp(prefix=".pending-", dir=path.parent)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def seal_backup(key, plaintext, context):
    nonce = os.urandom(12)
    return nonce + AESGCM(key).encrypt(nonce, plaintext, context)


def open_backup(key, ciphertext, context):
    if len(ciphertext) < 28:
        raise ValueError("truncated encrypted backup")
    return AESGCM(key).decrypt(ciphertext[:12], ciphertext[12:], context)
