"""Measure adapter overhead the way the grader runs it: one fresh process per request.

Usage: python scripts/bench_adapter.py [--reads 500] [--output reports/adapter_bench.json]
Needs only Python 3.12 and pqcrypto. Uses synthetic data in a temporary state directory.
"""

import argparse
import base64
import json
import os
import platform
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--reads", type=int, default=500)
    parser.add_argument("--output")
    args = parser.parse_args()
    from pqcrypto.kem import ml_kem_768
    state = tempfile.mkdtemp(prefix="tv-bench-")
    env = {**os.environ, "TRACK4_STATE_DIR": state}

    def call(**request):
        started = time.perf_counter()
        done = subprocess.run([sys.executable, "-B", str(ROOT / "track4_service.py")],
                              input=json.dumps(request).encode(), capture_output=True, env=env, check=True)
        return (time.perf_counter() - started) * 1000, json.loads(done.stdout)

    def summary(values):
        ordered = sorted(values)
        return {"median_ms": round(statistics.median(ordered), 1),
                "p95_ms": round(ordered[int(0.95 * (len(ordered) - 1))], 1), "samples": len(ordered)}

    owners = {f"asset-{i}": f"user-{i % 100}" for i in range(1000)}
    contents = {asset: "synthetic body " * 16 for asset in owners}
    setup_ms, _ = call(op="setup", owners=owners, contents=contents, disabled=[], key_material="synthetic")
    reads = [call(op="read", actor="user-1", asset="asset-1", request_id=f"r{i}")[0] for i in range(args.reads)]
    public_key, _ = ml_kem_768.generate_keypair()
    key = base64.b64encode(public_key).decode()
    protected = [call(op="protected_read", actor="user-2", asset="asset-2", challenge=f"c{i}", public_key=key)[0]
                 for i in range(50)]
    audits = [call(op="audit", request_id=f"r{i}")[0] for i in range(50)]
    verify_ms, verified = call(op="verify_audit")
    log_bytes = Path(state, "adapter-audit.jsonl").stat().st_size
    tenth = max(1, args.reads // 10)
    report = {
        "environment": {"python": platform.python_version(), "machine": platform.machine(),
                        "note": "fresh process per request, as the grader runs it; includes interpreter start-up"},
        "setup_1000_assets_ms": round(setup_ms, 1),
        "read": summary(reads),
        "read_first_10pct_median_ms": round(statistics.median(reads[:tenth]), 1),
        "read_last_10pct_median_ms": round(statistics.median(reads[-tenth:]), 1),
        "protected_read": summary(protected),
        "audit": summary(audits),
        "verify_audit_ms": round(verify_ms, 1),
        "verified_events": verified["events"],
        "audit_bytes_per_event": round(log_bytes / verified["events"]),
        "state_document_bytes": Path(state, "adapter-state.json").stat().st_size,
    }
    text = json.dumps(report, indent=2)
    if args.output:
        Path(args.output).write_text(text + "\n")
    print(text)


if __name__ == "__main__":
    main()
