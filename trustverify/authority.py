"""Local transactional authority shared by three independently running service nodes."""

import contextlib
import fcntl
import hashlib
import json
import os
import re
import sqlite3
import tempfile
import time
import uuid
from pathlib import Path

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives.asymmetric import mldsa

from .crypto import (atomic_write, b64, canonical, load_private, new_identity,
                     open_backup, private_bytes, public, seal_backup, sign, unb64, verify)
from .protocol import CHUNK_SIZE, validate_manifest

NODES = {"node-a": "frontend", "node-b": "billing", "node-c": "secrets"}
ZERO = "0" * 64
IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z")
STATE_TABLES = ("users", "devices", "keys", "permissions", "approvals", "transfers", "chunks")
SCHEMA = """
CREATE TABLE users (id TEXT PRIMARY KEY, role TEXT NOT NULL CHECK(role IN ('user','admin')));
CREATE TABLE devices (id TEXT PRIMARY KEY, owner TEXT NOT NULL REFERENCES users(id), version INTEGER NOT NULL, revoked INTEGER NOT NULL DEFAULT 0);
CREATE TABLE keys (device TEXT NOT NULL REFERENCES devices(id), version INTEGER NOT NULL, public TEXT NOT NULL, state TEXT NOT NULL CHECK(state IN ('active','retired','revoked')), PRIMARY KEY(device,version));
CREATE TABLE permissions (owner TEXT NOT NULL REFERENCES users(id), service TEXT NOT NULL, PRIMARY KEY(owner,service));
CREATE TABLE approvals (id TEXT PRIMARY KEY, owner TEXT NOT NULL, service TEXT NOT NULL, expires REAL NOT NULL, used INTEGER NOT NULL DEFAULT 0);
CREATE TABLE nonces (nonce TEXT PRIMARY KEY, node TEXT NOT NULL, expires REAL NOT NULL);
CREATE TABLE transfers (id TEXT PRIMARY KEY, sender TEXT NOT NULL, sender_version INTEGER NOT NULL, recipient TEXT NOT NULL, recipient_version INTEGER NOT NULL, manifest TEXT NOT NULL, status TEXT NOT NULL, expires REAL NOT NULL);
CREATE TABLE chunks (transfer_id TEXT NOT NULL REFERENCES transfers(id), idx INTEGER NOT NULL, body BLOB NOT NULL, PRIMARY KEY(transfer_id,idx));
CREATE TABLE audit (seq INTEGER PRIMARY KEY, body TEXT NOT NULL, signature TEXT NOT NULL);
CREATE TABLE meta (cluster TEXT NOT NULL);
"""


class Denied(Exception):
    def __init__(self, message, status=403):
        super().__init__(message)
        self.status = status


def identifier(value):
    if not isinstance(value, str) or not IDENTIFIER.fullmatch(value):
        raise ValueError("invalid identifier")
    return value


def connect(path):
    db = sqlite3.connect(Path(path).resolve().as_uri() + "?mode=rw", uri=True, timeout=5)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys=ON")
    db.execute("PRAGMA synchronous=FULL")
    return db


def state_digest(db):
    digest = hashlib.sha256()
    for table in STATE_TABLES:
        digest.update(table.encode("ascii"))
        for row in db.execute(f"SELECT * FROM {table} ORDER BY 1,2"):
            values = [hashlib.sha256(v).hexdigest() if isinstance(v, bytes) else v for v in row]
            digest.update(canonical(values) + b"\n")
    return digest.hexdigest()


def record_hash(body, signature):
    return hashlib.sha256(canonical({"body": body, "signature": signature})).hexdigest()


def verify_log(records, trust, anchor=None):
    """Public-key verification; requires a separately retained anchor to detect truncation."""
    previous, count, anchored = ZERO, 0, anchor is None
    if anchor is not None:
        verify(trust["audit_public"], "checkpoint", anchor["head"], anchor["signature"])
        if anchor["head"]["cluster"] != trust["cluster"]:
            raise ValueError("checkpoint cluster mismatch")
    for record in records:
        count += 1
        body = record["body"]
        if body["seq"] != count or body["previous"] != previous or body["cluster"] != trust["cluster"]:
            raise ValueError(f"audit chain failure at event {count}")
        verify(trust["audit_public"], "audit", body, record["signature"])
        previous = record_hash(body, record["signature"])
        if anchor and count == anchor["head"]["seq"]:
            if previous != anchor["head"]["hash"]:
                raise ValueError("audit checkpoint mismatch")
            anchored = True
    if not anchored:
        raise ValueError("audit truncated before retained checkpoint")
    return {"seq": count, "hash": previous, "cluster": trust["cluster"]}


class Authority:
    def __init__(self, directory, operator, *, fault=None, now=time.time, recovery_only=False):
        self.directory, self.operator = Path(directory), Path(operator)
        self.path = self.directory / "authority.sqlite"
        self.trust = json.loads((self.operator / "trust.json").read_bytes())
        self.audit_key = None if recovery_only else load_private((self.directory / "audit.pem").read_bytes())
        if self.audit_key is not None and public(self.audit_key) != self.trust["audit_public"]:
            raise ValueError("audit signing key does not match pinned trust root")
        self.fault, self.now = fault, now

    @classmethod
    def initialize(cls, directory, operator, admin_public):
        directory, operator = Path(directory), Path(operator)
        if directory.resolve() == operator.resolve() or directory.resolve() in operator.resolve().parents:
            raise ValueError("operator trust/checkpoints must be outside authority directory")
        if directory.exists() or operator.exists():
            raise ValueError("initialization requires new authority and operator directories")
        mldsa.MLDSA65PublicKey.from_public_bytes(unb64(admin_public))
        directory.mkdir(parents=True, mode=0o700)
        operator.mkdir(parents=True, mode=0o700)
        key = new_identity()
        trust = {"cluster": uuid.uuid4().hex, "audit_public": public(key)}
        atomic_write(operator / "trust.json", canonical(trust))
        atomic_write(operator / "recovery.key", os.urandom(32))
        atomic_write(directory / "audit.pem", private_bytes(key))
        with contextlib.closing(sqlite3.connect(directory / "authority.sqlite")) as db:
            db.executescript(SCHEMA)
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("PRAGMA synchronous=FULL")
            db.execute("INSERT INTO meta VALUES (?)", (trust["cluster"],))
            db.execute("INSERT INTO users VALUES ('operator','admin')")
            db.execute("INSERT INTO devices VALUES ('operator-device','operator',1,0)")
            db.execute("INSERT INTO keys VALUES ('operator-device',1,?,'active')", (admin_public,))
            for service in NODES.values():
                db.execute("INSERT INTO permissions VALUES ('operator',?)", (service,))
            db.commit()
        os.chmod(directory / "authority.sqlite", 0o600)
        authority = cls(directory, operator)
        with authority.locked(), contextlib.closing(connect(authority.path)) as db:
            db.execute("BEGIN IMMEDIATE")
            authority._append(db, "operator", "operator-device", "bootstrap", "authority", "allowed", {})
            db.commit()
            authority._checkpoint(db)
        return authority

    @contextlib.contextmanager
    def locked(self):
        fd = os.open(self.operator / "authority.lock", os.O_CREAT | os.O_RDWR, 0o600)
        with os.fdopen(fd, "rb") as stream:
            fcntl.flock(stream, fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(stream, fcntl.LOCK_UN)

    def _records(self, db):
        return [{"body": json.loads(r["body"]), "signature": r["signature"]}
                for r in db.execute("SELECT body,signature FROM audit ORDER BY seq")]

    def _head(self, db):
        row = db.execute("SELECT body,signature FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
        body = json.loads(row["body"])
        return {"seq": body["seq"], "hash": record_hash(body, row["signature"]),
                "cluster": self.trust["cluster"]}

    def _checkpoint(self, db):
        head = self._head(db)
        path = self.operator / "checkpoint.json"
        if path.exists():
            existing = json.loads(path.read_bytes())
            if existing["head"] == head:
                verify(self.trust["audit_public"], "checkpoint", head, existing["signature"])
                return
        atomic_write(path, canonical(
            {"head": head, "signature": sign(self.audit_key, "checkpoint", head)}))

    def _check_state(self, db, *, full=False):
        anchor = json.loads((self.operator / "checkpoint.json").read_bytes())
        if db.execute("SELECT cluster FROM meta").fetchone()[0] != self.trust["cluster"]:
            raise ValueError("authority cluster mismatch")
        head = self._head(db)
        verify(self.trust["audit_public"], "checkpoint", anchor["head"], anchor["signature"])
        if full or head != anchor["head"]:
            head = verify_log(self._records(db), self.trust, anchor)
        row = db.execute("SELECT body,signature FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
        body = json.loads(row["body"])
        verify(self.trust["audit_public"], "audit", body, row["signature"])
        if body["state_digest"] != state_digest(db):
            raise ValueError("authority state integrity failure")
        return head

    def recover(self):
        with self.locked(), contextlib.closing(connect(self.path)) as db:
            head = self._check_state(db, full=True)
            # A committed, valid tail may precede its checkpoint if the process crashed.
            self._checkpoint(db)
            return head

    def _append(self, db, actor, device, action, node, outcome, details):
        row = db.execute("SELECT seq,body,signature FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
        seq = row["seq"] + 1 if row else 1
        previous = record_hash(json.loads(row["body"]), row["signature"]) if row else ZERO
        body = {"seq": seq, "previous": previous, "cluster": self.trust["cluster"],
                "actor": actor, "device": device, "action": action, "node": node,
                "service": NODES.get(node, "authority"), "outcome": outcome,
                "observed_at": self.now(), "details": details, "state_digest": state_digest(db)}
        db.execute("INSERT INTO audit VALUES (?,?,?)", (seq, canonical(body).decode("ascii"),
                                                      sign(self.audit_key, "audit", body)))

    def challenge(self, node):
        if node not in NODES:
            raise ValueError("unknown node")
        with self.locked(), contextlib.closing(connect(self.path)) as db:
            self._check_state(db)
            with db:
                db.execute("DELETE FROM nonces WHERE expires<?", (self.now(),))
                if db.execute("SELECT COUNT(*) FROM nonces").fetchone()[0] >= 4096:
                    raise Denied("challenge capacity reached", 429)
                nonce = uuid.uuid4().hex + uuid.uuid4().hex
                db.execute("INSERT INTO nonces VALUES (?,?,?)", (nonce, node, self.now() + 30))
            return nonce

    def directory_entry(self, device):
        identifier(device)
        with self.locked(), contextlib.closing(connect(self.path)) as db:
            self._check_state(db)
            row = db.execute("SELECT d.id,d.owner,d.version,d.revoked,k.public,k.state FROM devices d JOIN keys k ON d.id=k.device AND d.version=k.version WHERE d.id=?", (device,)).fetchone()
            if row is None:
                raise Denied("unknown device", 404)
            value = dict(row)
            return {"entry": value, "signature": sign(self.audit_key, "directory", value)}

    def execute(self, node, request):
        if node not in NODES:
            raise ValueError("unknown node")
        if not isinstance(request, dict) or set(request) != {"node", "device", "version", "nonce", "action", "data", "signature"}:
            raise Denied("invalid request envelope", 400)
        actor, authenticated_device, failure = "unauthenticated", None, None
        details, result = {}, None
        with self.locked(), contextlib.closing(connect(self.path)) as db:
            self._check_state(db)
            db.execute("BEGIN IMMEDIATE")
            try:
                if request["node"] != node or not isinstance(request["data"], dict):
                    raise Denied("request binding mismatch", 400)
                identifier(request["device"])
                if type(request["version"]) is not int:
                    raise ValueError("invalid key version")
                key = db.execute("SELECT k.*,d.owner,d.revoked,d.version AS current_version,u.role FROM keys k JOIN devices d ON k.device=d.id JOIN users u ON d.owner=u.id WHERE k.device=? AND k.version=?", (request["device"], request["version"])).fetchone()
                if key is None:
                    raise Denied("unknown credential")
                verify(key["public"], "request", {k: v for k, v in request.items() if k != "signature"}, request["signature"])
                actor, authenticated_device = key["owner"], key["device"]
                nonce = db.execute("SELECT * FROM nonces WHERE nonce=?", (request["nonce"],)).fetchone()
                if nonce is None or nonce["node"] != node or nonce["expires"] < self.now():
                    raise Denied("expired, replayed or incorrectly bound request")
                db.execute("DELETE FROM nonces WHERE nonce=?", (request["nonce"],))
                if key["revoked"] or key["state"] == "revoked":
                    raise Denied("revoked device")
                if key["state"] != "active":
                    if request["action"] not in {"put_chunk", "finish", "fetch", "read_chunk"}:
                        raise Denied("retired key: new requests require current version")
                    self._transfer(db, request["data"]["transfer"], key)
                db.execute("SAVEPOINT operation")
                try:
                    result, details = self._dispatch(db, node, request["action"], request["data"], key)
                except Exception:
                    db.execute("ROLLBACK TO operation")
                    raise
            except (Denied, ValueError, TypeError, KeyError, InvalidSignature, sqlite3.IntegrityError) as exc:
                failure = exc if isinstance(exc, Denied) else Denied("invalid request or signature", 400)
                details = {"reason": str(failure)}
            except BaseException:
                db.rollback()
                raise
            try:
                self._append(db, actor, authenticated_device, request["action"] if isinstance(request["action"], str) else "invalid",
                             node, "denied" if failure else "allowed", details)
                db.commit()
                if not failure and request["action"] == "rotate" and self.fault:
                    self.fault("rotation_committed")
                self._checkpoint(db)
            except BaseException:
                db.rollback()
                raise
        if failure:
            raise failure
        return result

    def _permission(self, db, owner, service):
        if not db.execute("SELECT 1 FROM permissions WHERE owner=? AND service=?", (owner, service)).fetchone():
            raise Denied("service permission denied")

    def _transfer(self, db, transfer, key):
        row = db.execute("SELECT * FROM transfers WHERE id=?", (transfer,)).fetchone()
        if row is None:
            raise Denied("unknown transfer", 404)
        if not ((row["sender"] == key["device"] and row["sender_version"] == key["version"]) or
                (row["recipient"] == key["device"] and row["recipient_version"] == key["version"])):
            raise Denied("transfer identity/version mismatch")
        if row["expires"] < self.now():
            raise Denied("transfer grant expired")
        for device in (row["sender"], row["recipient"]):
            peer = db.execute("SELECT owner,revoked FROM devices WHERE id=?", (device,)).fetchone()
            if peer is None or peer["revoked"]:
                raise Denied("transfer peer revoked")
        return row

    def _dispatch(self, db, node, action, data, key):
        service = NODES[node]
        if action in {"enroll", "revoke", "approve", "grant", "remove_permission"} and key["role"] != "admin":
            raise Denied("administrator required")
        if action == "enroll":
            owner, device = identifier(data["owner"]), identifier(data["device"])
            proof = {"owner": owner, "device": device, "public": data["public"]}
            verify(data["public"], "enroll", proof, data["proof"])
            if db.execute("SELECT 1 FROM keys WHERE public=?", (data["public"],)).fetchone():
                raise Denied("key material already registered; generate a fresh device key")
            db.execute("INSERT OR IGNORE INTO users VALUES (?,'user')", (owner,))
            db.execute("INSERT INTO devices VALUES (?,?,1,0)", (device, owner))
            db.execute("INSERT INTO keys VALUES (?,1,?,'active')", (device, data["public"]))
            return {"version": 1}, {"owner": owner, "target_device": device}
        if action == "rotate":
            new_version = key["current_version"] + 1
            proof = {"device": key["device"], "version": new_version, "public": data["public"]}
            verify(data["public"], "rotation", proof, data["proof"])
            if db.execute("SELECT 1 FROM keys WHERE public=?", (data["public"],)).fetchone():
                raise Denied("key material already registered; rotation requires fresh material")
            db.execute("UPDATE keys SET state='retired' WHERE device=? AND state='active'", (key["device"],))
            db.execute("INSERT INTO keys VALUES (?,?,?,'active')", (key["device"], new_version, data["public"]))
            db.execute("UPDATE devices SET version=? WHERE id=?", (new_version, key["device"]))
            if self.fault:
                self.fault("rotation_staged")
            return {"version": new_version, "cutoff": "transaction commit for new admission",
                    "new_request_grace_seconds": 0,
                    "old_key_final_cutoff_no_later_than": self.now() + 120}, {"version": new_version}
        if action == "revoke":
            target = identifier(data["device"])
            row = db.execute("SELECT owner FROM devices WHERE id=?", (target,)).fetchone()
            if row is None:
                raise Denied("unknown device", 404)
            if row["owner"] == key["owner"]:
                raise Denied("cannot revoke own administrator devices")
            db.execute("UPDATE devices SET revoked=1 WHERE id=?", (target,))
            db.execute("UPDATE keys SET state='revoked' WHERE device=?", (target,))
            return {"revoked": target}, {"target_device": target, "owner": row["owner"]}
        if action == "approve":
            owner = identifier(data["owner"])
            target_service = data["service"]
            if target_service not in NODES.values() or not db.execute("SELECT 1 FROM users WHERE id=?", (owner,)).fetchone():
                raise ValueError("unknown owner or service")
            approval = uuid.uuid4().hex
            db.execute("INSERT INTO approvals VALUES (?,?,?, ?,0)", (approval, owner, target_service, self.now() + 300))
            return {"approval": approval}, {"approval": approval, "owner": owner, "target_service": target_service}
        if action in {"grant", "remove_permission"}:
            owner, target_service = identifier(data["owner"]), data["service"]
            if target_service not in NODES.values():
                raise ValueError("unknown service")
            approval = data.get("approval")
            approved = False
            if approval is not None:
                row = db.execute("SELECT * FROM approvals WHERE id=?", (approval,)).fetchone()
                if not row or row["used"] or row["owner"] != owner or row["service"] != target_service or row["expires"] < self.now():
                    raise Denied("invalid approval")
                approved = True
                db.execute("UPDATE approvals SET used=1 WHERE id=?", (approval,))
            if action == "grant":
                db.execute("INSERT OR IGNORE INTO permissions VALUES (?,?)", (owner, target_service))
            else:
                db.execute("DELETE FROM permissions WHERE owner=? AND service=?", (owner, target_service))
            return {"approved": approved}, {"owner": owner, "target_service": target_service, "approved": approved, "approval": approval}
        self._permission(db, key["owner"], service)
        if action == "access":
            note = data.get("note", "")
            if not isinstance(note, str) or len(note) > 2048:
                raise ValueError("note must be text, at most 2048 characters")
            return {"service": service, "actor": key["owner"]}, {"note": note}
        if action == "start":
            manifest = data["manifest"]
            binding = manifest["offer"]["binding"]
            peer = db.execute("SELECT k.public,d.owner,d.revoked FROM devices d JOIN keys k ON k.device=d.id AND k.version=d.version WHERE d.id=? AND d.version=?", (binding["recipient_device"], binding["recipient_version"])).fetchone()
            if peer is None or peer["revoked"]:
                raise Denied("recipient credential unavailable")
            binding = validate_manifest(manifest, key["public"], peer["public"])
            if binding["sender_device"] != key["device"] or binding["sender_version"] != key["version"]:
                raise Denied("sender binding mismatch")
            self._permission(db, peer["owner"], service)
            session = binding["session"]
            db.execute("INSERT INTO transfers VALUES (?,?,?,?,?,?,'pending',?)", (
                session, key["device"], key["version"], binding["recipient_device"], binding["recipient_version"],
                canonical(manifest).decode("ascii"), self.now() + 120))
            return {"transfer": session, "grant_seconds": 120}, {"transfer": session, "recipient": peer["owner"]}
        if action in {"put_chunk", "finish", "fetch", "read_chunk"}:
            transfer = self._transfer(db, data["transfer"], key)
            for device in (transfer["sender"], transfer["recipient"]):
                owner = db.execute("SELECT owner FROM devices WHERE id=?", (device,)).fetchone()[0]
                self._permission(db, owner, service)
            manifest = json.loads(transfer["manifest"])
            if action in {"put_chunk", "finish"} and transfer["sender"] != key["device"]:
                raise Denied("sender required")
            if action in {"fetch", "read_chunk"} and transfer["recipient"] != key["device"]:
                raise Denied("recipient required")
            if action == "put_chunk":
                if transfer["status"] != "pending":
                    raise Denied("transfer already committed")
                index, body = data["index"], unb64(data["body"])
                if type(index) is not int or not 0 <= index < manifest["chunks"]:
                    raise ValueError("invalid chunk index")
                expected = CHUNK_SIZE if index < manifest["chunks"] - 1 else manifest["ciphertext_bytes"] - index * CHUNK_SIZE
                if len(body) != expected:
                    raise ValueError("invalid chunk length")
                existing = db.execute("SELECT body FROM chunks WHERE transfer_id=? AND idx=?", (transfer["id"], index)).fetchone()
                if existing and existing[0] != body:
                    raise Denied("conflicting fragment")
                db.execute("INSERT OR IGNORE INTO chunks VALUES (?,?,?)", (transfer["id"], index, body))
                return {"stored": index}, {"transfer": transfer["id"], "index": index}
            if action == "finish":
                rows = db.execute("SELECT body FROM chunks WHERE transfer_id=? ORDER BY idx", (transfer["id"],)).fetchall()
                ciphertext = b"".join(r[0] for r in rows)
                if len(rows) != manifest["chunks"] or len(ciphertext) != manifest["ciphertext_bytes"] or hashlib.sha256(ciphertext).hexdigest() != manifest["ciphertext_hash"]:
                    raise Denied("delivery failed: incomplete or invalid ciphertext")
                db.execute("UPDATE transfers SET status='complete' WHERE id=?", (transfer["id"],))
                return {"status": "complete"}, {"transfer": transfer["id"]}
            if transfer["status"] != "complete":
                raise Denied("delivery not committed")
            if action == "fetch":
                return manifest, {"transfer": transfer["id"]}
            index = data["index"]
            if type(index) is not int or not 0 <= index < manifest["chunks"]:
                raise ValueError("invalid chunk index")
            row = db.execute("SELECT body FROM chunks WHERE transfer_id=? AND idx=?", (transfer["id"], index)).fetchone()
            if row is None:
                raise Denied("fragment unavailable", 404)
            return {"body": b64(row[0])}, {"transfer": transfer["id"], "index": index}
        raise Denied("unknown action", 400)

    def export_log(self):
        with self.locked(), contextlib.closing(connect(self.path)) as db:
            self._check_state(db, full=True)
            self._checkpoint(db)
            return {"trust": self.trust, "checkpoint": json.loads((self.operator / "checkpoint.json").read_bytes()),
                    "records": self._records(db)}

    def backup(self, destination):
        destination = Path(destination).resolve()
        if any(destination == root.resolve() or root.resolve() in destination.parents
               for root in (self.directory, self.operator)):
            raise ValueError("backup destination must be outside live authority and operator directories")
        with self.locked(), contextlib.closing(connect(self.path)) as db:
            self._check_state(db, full=True)
            self._checkpoint(db)
            with tempfile.TemporaryDirectory(prefix=".snapshot-", dir=self.directory) as temporary:
                snapshot_path = Path(temporary) / "snapshot.sqlite"
                with contextlib.closing(sqlite3.connect(snapshot_path)) as snapshot_db:
                    db.backup(snapshot_db)
                    snapshot_db.execute("PRAGMA journal_mode=DELETE")
                snapshot = snapshot_path.read_bytes()
            payload = canonical({"database": b64(snapshot), "audit_private": b64(private_bytes(self.audit_key))})
            ciphertext = seal_backup((self.operator / "recovery.key").read_bytes(), payload, canonical(self.trust))
            atomic_write(destination, ciphertext)
            return {"bytes": len(ciphertext), "head": self._head(db)}

    def restore(self, source):
        """Verify completely in memory before replacing any persistent key or database."""
        try:
            with Path(source).open("rb") as stream:
                ciphertext = stream.read(64 * 1024 * 1024 + 1)
            if len(ciphertext) > 64 * 1024 * 1024:
                raise ValueError("backup exceeds sandbox limit")
            payload = json.loads(open_backup((self.operator / "recovery.key").read_bytes(), ciphertext,
                                             canonical(self.trust)))
            restored_key = load_private(unb64(payload["audit_private"]))
            if public(restored_key) != self.trust["audit_public"]:
                raise ValueError("backup signing key mismatch")
            with self.locked(), contextlib.closing(sqlite3.connect(":memory:")) as db:
                db.row_factory = sqlite3.Row
                db.deserialize(unb64(payload["database"]))
                anchor = json.loads((self.operator / "checkpoint.json").read_bytes())
                head = verify_log(self._records(db), self.trust, anchor)
                if db.execute("SELECT cluster FROM meta").fetchone()[0] != self.trust["cluster"]:
                    raise ValueError("backup cluster mismatch")
                if head != anchor["head"]:
                    raise ValueError("backup is not the latest anchored state")
                last = json.loads(db.execute("SELECT body FROM audit ORDER BY seq DESC LIMIT 1").fetchone()[0])
                if state_digest(db) != last["state_digest"]:
                    raise ValueError("backup state digest mismatch")
                if db.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                    raise ValueError("backup SQLite integrity failure")
                # WAL-free output makes atomic database replacement unambiguous.
                db.execute("PRAGMA journal_mode=DELETE")
                restored = db.serialize()
                for suffix in ("-wal", "-shm"):
                    sidecar = Path(str(self.path) + suffix)
                    if sidecar.exists():
                        sidecar.unlink()
                atomic_write(self.path, restored)
                atomic_write(self.directory / "audit.pem", private_bytes(restored_key))
                self.audit_key = restored_key
            return {"restored": True, "head": head}
        except (InvalidTag, InvalidSignature, ValueError, KeyError, TypeError, sqlite3.Error) as exc:
            raise ValueError("backup verification failed; no unverified key material used") from exc
