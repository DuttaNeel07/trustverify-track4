"""Deterministic synthetic evaluation data. These values are labels, never secrets."""

import json
import random
from pathlib import Path


def make_events(seed=2026):
    rng = random.Random(seed)
    events = []

    def add(actor, action, service, occurred, malicious=False, outcome="allowed", details=None):
        offset = rng.choice([-120, -80, 0, 70, 120])
        events.append({"id": f"e{len(events) + 1:05}", "actor": actor, "action": action,
                       "service": service, "outcome": outcome, "details": details or {},
                       "source_at": occurred + offset, "clock_offset": offset,
                       "clock_offset_trusted": True,
                       "observed_at": occurred + rng.randint(0, 12), "malicious": malicious})

    for worker in range(20):
        for step in range(50):
            add(f"worker-{worker}", "access", "frontend" if step % 2 == 0 else "billing",
                worker * 2 + step * 20)
    for change in range(20):
        when = 1100 + change * 100
        owner = f"approved-{change}"
        add("operator", "grant", "frontend", when, details={"owner": owner, "target_service": "secrets", "approved": True, "approval": f"approved-{change}"})
        add(owner, "access", "frontend", when + 20)
        add(owner, "access", "secrets", when + 35)
    for attack in range(20):
        when = 1200 + attack * 100
        owner = f"compromised-{attack}"
        add("operator", "grant", "frontend", when, True, details={"owner": owner, "target_service": "secrets", "approved": False, "approval": None})
        add(owner, "access", "frontend", when + 20)
        add(owner, "access", "secrets", when + 35, True)
        add(owner, "access", "secrets", when + 50, True, "denied", {"reason": "revoked device"})
    # Valid credentials, no privilege change: detection must still flag the observed path.
    for attack in range(10):
        when = 1500 + attack * 100
        add(f"lateral-only-{attack}", "access", "billing", when)
        add(f"lateral-only-{attack}", "access", "secrets", when + 20, True)
    # Timing problems are notices, not invented chronological attack paths.
    add("skewed", "access", "frontend", 3500)
    events[-1]["clock_offset"] = 121
    add("unknown-offset", "access", "billing", 3501)
    events[-1]["clock_offset_trusted"] = False
    return sorted(events, key=lambda event: (event["observed_at"], event["id"]))


if __name__ == "__main__":
    destination = Path(__file__).resolve().parents[1] / "fixtures" / "labelled_logs.json"
    destination.parent.mkdir(exist_ok=True)
    destination.write_text(json.dumps(make_events(), indent=2) + "\n")
    print(destination)
