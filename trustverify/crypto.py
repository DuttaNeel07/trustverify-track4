"""Library primitives only: ML-DSA-65, hybrid HPKE and AES-256-GCM.

This module needs the optional ``cryptography`` dependency (the ``messaging``
extra). The grader adapter never imports it; see ``trustverify.adapter``.
"""

import os

from cryptography.hazmat.primitives import hpke, serialization
from cryptography.hazmat.primitives.asymmetric import mldsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Re-exported for existing callers; implemented with the standard library only.
from .encoding import atomic_write, b64, canonical, unb64  # noqa: F401

SUITE = hpke.Suite(hpke.KEM.MLKEM768_X25519, hpke.KDF.HKDF_SHA256,
                   hpke.AEAD.AES_256_GCM)
DOMAIN = b"trustverify/v1/"


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


def seal_backup(key, plaintext, context):
    nonce = os.urandom(12)
    return nonce + AESGCM(key).encrypt(nonce, plaintext, context)


def open_backup(key, ciphertext, context):
    if len(ciphertext) < 28:
        raise ValueError("truncated encrypted backup")
    return AESGCM(key).decrypt(ciphertext[:12], ciphertext[12:], context)
