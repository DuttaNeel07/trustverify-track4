"""Track 4 adapter v1 application: owner-bound reads, revocation and signed audit.

Runs on Python 3.12 with only the standard library and ``pqcrypto==0.4.0``,
which is exactly what the offline judging runtime provides. It never imports
``cryptography``.

Policy, in order, for ``read`` and ``protected_read``:
1. the actor must be a well-formed identifier,
2. the actor must not be disabled at setup or revoked later,
3. the asset must exist and be owned by that actor.
Anything else is denied without disclosing content.

Every decision is appended to a hash-chained audit log whose records are signed
with a per-setup ML-DSA-65 key. State is written atomically (temp file, fsync,
rename) under an exclusive lock before the reply is printed.
"""

import contextlib
import fcntl
import hashlib
import hmac
import json
import os
import re
import tempfile
import time
import uuid
from pathlib import Path

from pqcrypto.kem import ml_kem_768
from pqcrypto.sign import ml_dsa_65

from .encoding import atomic_write, b64, canonical, unb64

FORMAT = "trustverify/adapter/v1"
DOMAIN = b"trustverify/adapter/v1/audit\x00"
ZERO = "0" * 64
ML_KEM_768_PUBLIC_BYTES = 1184
MAX_ID = 256
MAX_CHALLENGE = 4096
MAX_ENTRIES = 10_000
MAX_BODY = 1024 * 1024
# Identifiers are opaque to the adapter; reject only control characters and oversize values.
IDENTIFIER = re.compile(r"[^\x00-\x1f\x7f]{1,%d}\Z" % MAX_ID)


class RequestError(ValueError):
    """Malformed request. Message never contains request values."""


def state_directory():
    configured = os.environ.get("TRACK4_STATE_DIR")
    base = Path(configured) if configured else Path(tempfile.gettempdir()) / "trustverify-track4"
    base.mkdir(parents=True, exist_ok=True, mode=0o700)
    return base


def _identifier(value, field):
    if not isinstance(value, str) or not IDENTIFIER.fullmatch(value):
        raise RequestError(f"invalid {field}")
    return value


def _record_hash(record):
    return hashlib.sha256(canonical(record)).hexdigest()


class Store:
    """One JSON document per state directory, replaced atomically."""

    def __init__(self, directory):
        self.directory = Path(directory)
        self.path = self.directory / "adapter-state.json"
        self.key_path = self.directory / "adapter-audit.key"

    @contextlib.contextmanager
    def locked(self):
        fd = os.open(self.directory / "adapter.lock", os.O_CREAT | os.O_RDWR, 0o600)
        with os.fdopen(fd, "rb") as stream:
            fcntl.flock(stream, fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(stream, fcntl.LOCK_UN)

    def load(self):
        if not self.path.exists():
            return None
        state = json.loads(self.path.read_bytes())
        if state.get("format") != FORMAT:
            raise RequestError("unsupported state format")
        head = state["audit"][-1] if state["audit"] else None
        expected = _record_hash(head) if head else ZERO
        if state["head"] != expected:
            raise RequestError("audit head mismatch; state integrity failure")
        return state

    def save(self, state):
        atomic_write(self.path, canonical(state))

    def signing_key(self):
        return self.key_path.read_bytes()


def _append(store, state, event):
    body = {"seq": len(state["audit"]) + 1, "previous": state["head"],
            "instance": state["instance"], "at": time.time(), **event}
    signature = ml_dsa_65.sign(store.signing_key(), DOMAIN + canonical(body))
    record = {"body": body, "signature": b64(signature)}
    state["audit"].append(record)
    state["head"] = _record_hash(record)
    if body.get("request_id") is not None:
        state["decisions"][body["request_id"]] = body["decision"]


def verify_audit(state):
    """Check sequence, hash chain and every ML-DSA-65 signature."""
    public_key = unb64(state["audit_public"])
    previous = ZERO
    for count, record in enumerate(state["audit"], 1):
        body = record["body"]
        if body["seq"] != count or body["previous"] != previous or body["instance"] != state["instance"]:
            raise RequestError(f"audit chain failure at event {count}")
        if not ml_dsa_65.verify(public_key, DOMAIN + canonical(body), unb64(record["signature"])):
            raise RequestError(f"audit signature failure at event {count}")
        previous = _record_hash(record)
    if previous != state["head"]:
        raise RequestError("audit head mismatch")
    return {"verified": True, "events": len(state["audit"]), "head": previous}


def _decide(state, actor, asset):
    """Return (decision, reason). Reasons are fixed strings, never request data."""
    if actor in state["revoked"]:
        return "deny", "actor revoked"
    if actor in state["disabled"]:
        return "deny", "actor disabled"
    if state["owners"].get(asset) != actor:
        return "deny", "not the asset owner"
    return "allow", "owner"


def setup(store, request):
    owners, contents = request.get("owners"), request.get("contents")
    disabled = request.get("disabled", [])
    if not isinstance(owners, dict) or not isinstance(contents, dict) or not isinstance(disabled, list):
        raise RequestError("setup needs owners, contents and disabled")
    if len(owners) > MAX_ENTRIES or len(contents) > MAX_ENTRIES or len(disabled) > MAX_ENTRIES:
        raise RequestError("setup exceeds sandbox limits")
    for asset, actor in owners.items():
        _identifier(asset, "asset")
        _identifier(actor, "owner")
    for asset, body in contents.items():
        _identifier(asset, "asset")
        if not isinstance(body, str) or len(body.encode("utf-8")) > MAX_BODY:
            raise RequestError("content must be text, at most 1 MiB")
    for actor in disabled:
        _identifier(actor, "disabled actor")
    # key_material is synthetic and sensitive: it is accepted but never stored or echoed.
    public_key, secret_key = ml_dsa_65.generate_keypair()
    atomic_write(store.key_path, secret_key)
    state = {"format": FORMAT, "instance": uuid.uuid4().hex, "audit_public": b64(public_key),
             "owners": owners, "contents": contents, "disabled": sorted(set(disabled)),
             "revoked": [], "decisions": {}, "audit": [], "head": ZERO}
    _append(store, state, {"op": "setup", "actor": None, "asset": None, "request_id": None,
                           "decision": "allow", "reason": "initialized",
                           "assets": len(owners), "disabled": len(state["disabled"])})
    store.save(state)
    return {"ready": True}


def read(store, state, request):
    request_id = _identifier(request.get("request_id"), "request_id")
    if request_id in state["decisions"]:
        # Never overwrite the recorded decision of an earlier request.
        return {"decision": "deny"}
    try:
        actor = _identifier(request.get("actor"), "actor")
        asset = _identifier(request.get("asset"), "asset")
        decision, reason = _decide(state, actor, asset)
    except RequestError:
        actor, asset, decision, reason = None, None, "deny", "malformed request"
    _append(store, state, {"op": "read", "actor": actor, "asset": asset, "request_id": request_id,
                           "decision": decision, "reason": reason})
    store.save(state)
    if decision == "allow":
        return {"decision": "allow", "body": state["contents"][asset]}
    return {"decision": "deny"}


def revoke(store, state, request):
    actor = _identifier(request.get("actor"), "actor")
    already = actor in state["revoked"]
    if not already:
        state["revoked"].append(actor)
    _append(store, state, {"op": "revoke", "actor": actor, "asset": None, "request_id": None,
                           "decision": "allow", "reason": "already revoked" if already else "revoked"})
    store.save(state)
    return {"revoked": True}


def audit(state, request):
    request_id = _identifier(request.get("request_id"), "request_id")
    decision = state["decisions"].get(request_id)
    if decision is None:
        # Unknown requests were never allowed; report that without inventing a record.
        return {"request_id": request_id, "decision": "deny", "recorded": False}
    return {"request_id": request_id, "decision": decision, "recorded": True}


def protected_read(store, state, request):
    challenge = request.get("challenge")
    try:
        actor = _identifier(request.get("actor"), "actor")
        asset = _identifier(request.get("asset"), "asset")
        if not isinstance(challenge, str) or not 0 < len(challenge) <= MAX_CHALLENGE:
            raise RequestError("invalid challenge")
        public_key = unb64(request.get("public_key"))
        if len(public_key) != ML_KEM_768_PUBLIC_BYTES:
            raise RequestError("public_key must be a raw ML-KEM-768 key")
        decision, reason = _decide(state, actor, asset)
    except (RequestError, ValueError):
        actor, asset, decision, reason = None, None, "deny", "malformed request"
    _append(store, state, {"op": "protected_read", "actor": actor, "asset": asset, "request_id": None,
                           "decision": decision, "reason": reason,
                           "challenge_sha256": hashlib.sha256(challenge.encode("utf-8")).hexdigest()
                           if isinstance(challenge, str) else None})
    store.save(state)
    if decision != "allow":
        return {"decision": "deny"}
    ciphertext, shared_secret = ml_kem_768.encrypt(public_key)
    proof = hmac.new(shared_secret, (challenge + state["contents"][asset]).encode("utf-8"),
                     hashlib.sha256).hexdigest()
    del shared_secret
    return {"decision": "allow", "ciphertext": b64(ciphertext), "proof": proof}


def dispatch(request, directory=None):
    if not isinstance(request, dict):
        raise RequestError("request must be a JSON object")
    store = Store(directory or state_directory())
    op = request.get("op")
    with store.locked():
        if op == "setup":
            return setup(store, request)
        state = store.load()
        if state is None:
            if op in {"read", "protected_read"}:
                return {"decision": "deny"}
            if op == "audit":
                return {"request_id": request.get("request_id"), "decision": "deny", "recorded": False}
            raise RequestError("setup required")
        if op == "read":
            return read(store, state, request)
        if op == "revoke":
            return revoke(store, state, request)
        if op == "audit":
            return audit(state, request)
        if op == "protected_read":
            return protected_read(store, state, request)
        if op == "verify_audit":
            return verify_audit(state)
    raise RequestError("unknown op")
