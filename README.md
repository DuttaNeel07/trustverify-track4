# TrustVerify — Track 4: Trust, but verify

Public source: [jayantkageri/trustverify-track4](https://github.com/jayantkageri/trustverify-track4).

A working organizer-sandbox prototype that connects **post-quantum encrypted transfers, device/key lifecycle controls, verifiable access decisions and contextual detection**. No AI/ML components, hard-coded secrets or custom cryptographic primitives.

**USP:** every sensitive transfer has an explainable authorization decision, an explicit key version and a verifiable audit trail, including through rotation, revocation and recovery.

This repository implements three independent HTTP enforcement processes backed by **one local transactional authority**. It does not implement three replicated key stores or distributed consensus. All endpoints bind to `127.0.0.1`; use only synthetic identities and files in the assigned sandbox.

Clients refuse HTTP redirects so a mock service cannot redirect requests outside its configured endpoint.

## Clean-machine setup

Requires Linux, Python 3.12 or newer, and Internet access during dependency installation. The crash tests use Linux `fork` and the authority uses POSIX file locking. No database server, PQ library build, API key or account is required. Cryptography wheels include their OpenSSL backend on supported platforms.

From the repository root:

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install '.[dev]'
python -m pytest -q
python -m trustverify demo --directory runtime/first-demo
```

The demo directory must be new. Choose another directory for a second run; prior keys and evidence are never overwritten. The demo launches all three services, makes real signed HTTP requests, runs assertions and stops the processes. A failed check exits nonzero.

Alternatively, with [uv](https://docs.astral.sh/uv/):

```sh
uv sync --extra dev --locked
uv run --extra dev --locked pytest -q
uv run --locked trustverify demo --directory runtime/first-demo
```

Runtime dependency: `cryptography==50.0.2`. Development/document dependencies: `pytest==9.2.0`, `reportlab==5.1.2`. The exact transitive resolution is in [uv.lock](uv.lock). Algorithm and library attribution is in [THIRD_PARTY.md](THIRD_PARTY.md).

[GitHub Actions verification](https://github.com/jayantkageri/trustverify-track4/actions) installs the project on a fresh Linux runner, runs all tests and the three-process demo, verifies its audit export, regenerates the PDF, and builds/tests/runs the Docker image without external runtime networking. See [.github/workflows/verify.yml](.github/workflows/verify.yml).

## Run and inspect the evidence

The demo produces:

| File | Purpose |
|---|---|
| `runtime/first-demo/report.json` | Asserted checklist outcomes and measured overhead/revocation observations |
| `runtime/first-demo/audit-export.json` | Signed, hash-linked events with original authenticated actors |
| `runtime/first-demo/alerts.json` | Identity, services, event IDs and explanations for alerts on the real demo log |
| `runtime/first-demo/operator/trust.json` | Pinned audit public key and cluster identity |
| `runtime/first-demo/operator/checkpoint.json` | Separately retained signed log checkpoint |
| `runtime/first-demo/keys.backup` | Encrypted, authenticated authority/key backup |
| `runtime/first-demo/identities/` | Fresh synthetic endpoint signing keys; never publish |
| `runtime/first-demo/inbox-bob/` | Local encrypted recipient inbox and its separate storage key; never publish |

Verify using the independently retained trust and checkpoint files, rather than trusting a public key supplied inside an exported log:

```sh
python -m trustverify verify \
  --log runtime/first-demo/audit-export.json \
  --trust runtime/first-demo/operator/trust.json \
  --checkpoint runtime/first-demo/operator/checkpoint.json

python -m trustverify detect \
  --log runtime/first-demo/audit-export.json \
  --trust runtime/first-demo/operator/trust.json \
  --checkpoint runtime/first-demo/operator/checkpoint.json

python -m trustverify evaluate --output reports/detector.json
```

`runtime/`, private keys, backups, local databases and virtual environments are excluded from Git and Docker build contexts. Only the non-secret measurement summaries belong in `reports/`.

## Architecture and trust boundaries

```text
Sender endpoint                         Recipient endpoint
ML-DSA signing key                      ML-DSA signing key
                                        one-use hybrid KEM private key
       signed offer + hybrid HPKE ciphertext
                       |
                       v
   node-a/frontend   node-b/billing   node-c/secrets
             three loopback HTTP processes
                       |
     shared SQLite authority + cross-process lock
     device registry / permissions / revocation tombstones
     admitted transfers / ciphertext fragments / signed audit
                       |
     separate operator trust root, checkpoint and recovery key
                       |
       verified log export -> explainable detector
```

The endpoints hold encryption secrets. Service nodes see encrypted payloads, public keys, signed manifests and access metadata. The local demo orchestrator simulates both endpoints; separate machines and a production E2EE client UI are outside this prototype.

### Cryptography and authenticated requests

- **Identity:** library ML-DSA-65 signatures, with separate application-purpose prefixes for requests, recipient offers, manifests, audit records and checkpoints.
- **Encryption:** the library's HPKE `MLKEM768_X25519`/X-Wing hybrid KEM, HKDF-SHA256 and AES-256-GCM. ML-KEM-768 is standardized in FIPS 203; ML-DSA-65 in FIPS 204. The PQ/hybrid HPKE integration is a draft extension; the application protocol is not Signal, Noise, or an independently audited standard.
- **Recipient binding:** a recipient signs a fresh offer binding the protocol, session ID, both device identities and key versions, and its ephemeral KEM public keys. The sender verifies that offer and signs the ciphertext manifest. The entire binding is HPKE `info`. Changing recipient information fails verification/decryption.
- **Request authentication:** the authority issues a 30-second, one-use random challenge. ML-DSA authenticates the complete node/action/device/version/challenge/data envelope. Challenges are consumed transactionally; cross-node and duplicate requests fail. A challenge nonce is distinct from a library-managed encryption nonce.
- **Authorization:** registered ownership, current key state, administrator role and service permission are checked by the authority. Transfer continuation additionally checks both participants' revocation and current service permissions.
- **Forward secrecy:** recipient KEM secrets are created per session, held only in endpoint memory, and dropped after success/failure. They are never backed up. Long-term signing keys alone do not decrypt prior completed sessions. Python does not guarantee physical zeroization of freed memory; process-memory compromise is excluded.
- **Completed inbox:** plaintext is committed only after full authentication and is encrypted locally under a separate random AES-256 storage key. That storage key is not derived from the identity key and is not sent to the authority.

### Rotation, revocation and recovery policy

**Rotation cutoff is the authority transaction commit. New-request grace period: zero.** Devices rotate their signing credential with proof of possession of the replacement. All nodes re-read authoritative state rather than accepting cached permissions. A previously admitted transfer can continue with its original credential for **120 seconds from admission**, provided both participants remain unrevoked and permitted. This is an explicit continuation exception, not permission to admit new work with a retired key. Keep the old signing key locally while finishing such a transfer.

The final cutoff for **all** old-key use is no later than 120 seconds after rotation: every pre-existing transfer grant expires by then, usually earlier. The rotation response reports that upper-bound deadline. Retired material cannot be reused for enrolment or another rotation.

**Revocation overrides continuation.** Every request/fragment checks current device state. All key versions of the lost device receive permanent revocation tombstones. An operator can enrol a new device for the same owner; permissions belong to the owner, so unrelated users retain access. The replacement does not inherit the lost device's local inbox storage key.

**Consistent recovery:** lifecycle changes, access outcomes and their audit event commit in one SQLite transaction. Fault injection kills an actual process before rotation commit and after commit but before checkpoint publication. Recovery validates the pinned signature chain, retained checkpoint and current state digest. It rolls back an incomplete change or accepts a fully committed valid tail. Revoked keys remain revoked.

**Authority outages fail closed.** Admission and continuation stop if the shared authority is unavailable. Clock offsets supplied in access logs cannot influence authorization. Authorization uses transaction order and the trusted authority host's expiry clock; that host's clock and filesystem are trusted.

### Backup and audit integrity

Backups contain a consistent SQLite snapshot (public registry, revocations, ciphertext and audit history) plus the audit signing key, encrypted/authenticated with AES-256-GCM under `operator/recovery.key`. The recovery key and signed freshness checkpoint stay outside the authority directory. Private endpoint identity keys and ephemeral secrets are not in this backup.

Restore authenticates the complete backup before using its key material, verifies the pinned signing key, full log chain, current state digest and SQLite integrity, and requires the snapshot to match the latest retained checkpoint exactly. **An older authentic backup is refused**, even if its encryption tag is valid, to prevent revocation rollback. Any later audited request makes the prior snapshot stale. Stop services before taking the recovery snapshot; historical rollback recovery is intentionally unsupported. Backups larger than 64 MiB are outside the sandbox limit.

Every audit record is canonically serialized, individually ML-DSA signed and linked to the preceding record. Its actor comes from verified credentials. User text remains nested in `details`; newlines cannot introduce another event. A separate signed checkpoint exposes deletion of an acknowledged log suffix. Historical public verification does not depend on rotated device keys because the audit key has a separate lifetime.

The cross-process lock spans transaction commit and atomic checkpoint publication. A crash may leave an unacknowledged committed tail, which recovery validates and adopts. Truncation of an uncheckpointed, unacknowledged tail is not detectable independently. Audit-key rotation is not implemented; compromise of that key is outside the retained-history guarantee.

## Detection and evaluation

Rules detect:

1. Administrator privilege grants without a validated, owner/service-matching, unexpired, single-use approval.
2. Use of revoked devices or transfer peers.
3. Observed consecutive service transitions outside the approved `frontend <-> billing` workflow, within 60 seconds and without a recent approved grant for that destination service.

Alerts identify the beneficiary identity, acting identity, services, supporting immutable event IDs, rule and explanation. A currently valid credential can still trigger a service-transition alert. Approved administration is context, not a blanket exclusion for all administrators. This is a small workflow-specific detector, not a general UEBA system.

**Timing bounds:** trusted source offsets up to **±120 seconds**, and corrected event arrival lateness up to **30 seconds**. A watermark buffer orders events within that range. Untrusted offsets, equal ambiguous timestamps and out-of-range events produce timing notices; ambiguous events cannot establish a definite service path. Non-temporal revocation/privilege checks still run. Offset estimates must come from a trusted collector, never arbitrary client fields. Authority-native events already use the authority clock.

For an identity with uncertain ordering, path alerts are conservatively withheld for that entire analysis batch. Timing notices list the affected identities; an uncertain permission change also marks its beneficiary. This avoids asserting a path across missing ordering information, at the cost of reduced path coverage for that batch. Other identities and non-temporal rules remain active. Every trusted collector arrival advances the watermark, including arrivals with unsupported source clocks.

The detector is an offline operator command. End-of-input flush advances the simulated collector clock by 30 seconds; it is not a continuously running alert daemon. The reported time-to-alert includes buffering and that flush.

[fixtures/labelled_logs.json](fixtures/labelled_logs.json) has **1,162 labelled events: 1,092 benign and 70 malicious**. It includes approved administration, routine frontend/billing traffic, unapproved grants, valid-credential lateral movement, revoked use, skew and reordered arrival. Labels are never read by detection rules. Tests additionally use two different randomized arrival/offset seeds.

Event-level evaluation counts each trigger event once; supporting context events are not predictions. F1 includes missed attacks. False alerts per 1,000 benign events use the complete benign-event denominator. Median alert latency is computed for detected malicious events from corrected occurrence time to simulated emission; missed events are reported separately.

The checked-in synthetic result is **F1 1.0**, **median 51 seconds**, **0 false alerts per 1,000 benign events**. This deliberately small, rule-aligned fixture does not establish performance on real access logs. See [reports/detector.json](reports/detector.json).

## Objective-to-evidence checklist

| Track 4 objective | Implementation / evidence |
|---|---|
| Key rotation | Zero admission grace; all-node rejection; admitted transfer finishes (`test_rotation_cutoff_all_nodes_and_transfer_continuity`) |
| Revocation / device loss | All-node rejection; measured observation upper bounds; re-enrolment; other user retains access |
| Crash recovery | Real process termination at both commit boundaries; pinned log/state recovery; revoked key stays revoked |
| Backup integrity | Bit-flipped backup rejected; fresh restore succeeds; stale restore rejected; missing key/database recovered |
| Log integrity | Newline/forged-actor injection, modified actor, deleted record and truncated suffix tests; public verification CLI |
| Routine / suspicious activity | Trusted approval validation; labelled F1, alert latency and false-alert report |
| Lateral movement | Valid credentials on unexpected observed service paths; supporting event IDs and rule explanation |
| Clock differences | ±120 s offset / 30 s lateness; reorder buffer; uncertain-order notices |
| Replay / recipient binding | Durable completed-message IDs; consumed request challenges; changed recipient and other identity rejected |
| Forward secrecy | One-use ephemeral recipient secrets excluded from backups; identity key cannot decrypt a completed recording |
| Loss / reordering | Numbered bounded ciphertext fragments; selective retry; full manifest/hash/signature/AEAD validation; no partial delivery |
| Session resumption | **Unsupported.** Interrupted sessions require a fresh signed offer; session ID alone is never a bearer credential |

See [tests/](tests/), [reports/demo.json](reports/demo.json), [THREAT_MODEL.md](THREAT_MODEL.md) and [DEMO.md](DEMO.md).

## Keep the mock services running

```sh
python -m trustverify init --directory runtime/manual
python -m trustverify serve --state runtime/manual/authority --operator runtime/manual/operator --node node-a --port 8101
```

In two other terminals, run the same command with `node-b --port 8102` and `node-c --port 8103`. Stop with Ctrl-C. The init command creates an operator signing identity; no default password exists.

For a signed operator access request:

```sh
python -m trustverify call --url http://127.0.0.1:8101 --node node-a \
  --identity runtime/manual/identities/operator \
  --trust runtime/manual/operator/trust.json --action access --data '{"note":"approved test"}'

python -m trustverify rotate --url http://127.0.0.1:8101 --node node-a \
  --identity runtime/manual/identities/operator --trust runtime/manual/operator/trust.json
```

`call --data @file.json` accepts a JSON object from a file. A device's `Identity.enrollment(owner)` helper creates its proof of possession. `Client.call("enroll", **proof)` is operator-only. The full protected file workflow is available through `protocol.Receiver`, `protocol.encrypt` and the documented `start`, `put_chunk`, `finish`, `fetch`, `read_chunk` actions in [demo.py](trustverify/demo.py).

`rotate` writes the candidate key before requesting the transaction. If transport fails, it retains the candidate. Reconcile the signed directory version with the saved `vN.pem` before retrying; do not delete the candidate or assume the request failed.

For offline backup/restore, stop service processes first:

```sh
python -m trustverify backup --state runtime/manual/authority --operator runtime/manual/operator --output runtime/manual/latest.backup
python -m trustverify restore --state runtime/manual/authority --operator runtime/manual/operator --input runtime/manual/latest.backup
python -m trustverify recover --state runtime/manual/authority --operator runtime/manual/operator
```

Export a fresh audit log after additional requests. An old export intentionally fails verification against a newer independently retained checkpoint.

## Container option

```sh
docker build -t trustverify .
docker run --rm --network none trustverify
docker run --rm --network none trustverify python -m pytest -q -p no:cacheprovider
```

The container launches only loopback services and runs as an unprivileged user. Docker is optional; the Python setup and subprocess integration tests are the primary checked path.

## Submission artifacts and limits

- Two-page brief: [docs/project-brief.pdf](docs/project-brief.pdf). Page two is the one-page threat model.
- Five-minute walkthrough script: [DEMO.md](DEMO.md).
- Public repository/video URLs: [submission.json](submission.json). **The video URL is intentionally blank at the user's request.**
- Regenerate the PDF: `python scripts/build_brief.py`. Fill the URL fields in `submission.json` when available; populated URLs become clickable PDF links.

Known limits: trusted single-host control plane and OS, loopback HTTP without TLS, central availability dependency, 1 MiB message limit, 120-second admission grants, offline workflow-specific detection, no audit-key rotation, no session resumption, no post-compromise healing and no claim of independently audited or production-secure application protocol. Revocation cannot erase plaintext or keys already copied by a recipient. Whole-state hashing favors auditability over throughput and needs redesign for large stores.

Publish only source/public evidence, and supply the required public five-minute recording before final submission.
