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


def make_heldout_events(seed=7):
    """Held-out set written after the rules, with cases the rules are known to miss or misjudge.

    Identities are neutral (``u-###``) and shuffled so names carry no signal. Benign and
    malicious cases interleave in time. Expected weak spots are included on purpose:
    approved-edge insider access, slow lateral movement beyond the path window, and benign
    use of an approval after its window.
    """
    rng = random.Random(seed)
    names = [f"u-{n:03}" for n in rng.sample(range(1000), 200)]
    events, clock = [], [0]

    def who():
        return names.pop()

    def add(actor, action, service, occurred, malicious=False, outcome="allowed", details=None):
        offset = rng.choice([-90, -30, 0, 30, 90])
        events.append({"id": f"h{len(events) + 1:05}", "actor": actor, "action": action,
                       "service": service, "outcome": outcome, "details": details or {},
                       "source_at": occurred + offset, "clock_offset": offset,
                       "clock_offset_trusted": True,
                       "observed_at": occurred + rng.randint(0, 20), "malicious": malicious})

    def slot():
        clock[0] += rng.randint(150, 400)
        return clock[0]

    def grant(owner, when, approved, approved_by="security-officer", malicious=False):
        add("operator", "grant", "frontend", when, malicious, details={
            "owner": owner, "target_service": "secrets", "approved": approved,
            "approval": "a-" + owner if approved else None, "approved_by": approved_by if approved else None})

    cases = (["benign_worker"] * 10 + ["benign_approved"] * 8 + ["benign_late_approved"] * 4 +
             ["benign_direct"] * 4 + ["unapproved_grant"] * 8 + ["self_approved"] * 4 +
             ["lateral"] * 8 + ["insider_approved_edge"] * 6 + ["slow_lateral"] * 4 + ["revoked_use"] * 4)
    rng.shuffle(cases)
    for case in cases:
        when, user = slot(), who()
        if case == "benign_worker":
            for step in range(20):
                add(user, "access", "frontend" if step % 2 == 0 else "billing", when + step * rng.randint(5, 15))
            clock[0] += 300
        elif case == "benign_approved":
            grant(user, when, True)
            add(user, "access", "frontend", when + rng.randint(10, 60))
            add(user, "access", "secrets", when + rng.randint(80, 110))
        elif case == "benign_late_approved":
            grant(user, when, True)
            add(user, "access", "frontend", when + 360)
            add(user, "access", "secrets", when + 380)
        elif case == "benign_direct":
            grant(user, when, True)
            add(user, "access", "secrets", when + rng.randint(20, 200))
        elif case == "unapproved_grant":
            grant(user, when, False, malicious=True)
            add(user, "access", "frontend", when + 20)
            add(user, "access", "secrets", when + 40, True)
        elif case == "self_approved":
            grant(user, when, True, approved_by="operator", malicious=True)
            add(user, "access", "secrets", when + 30, True)
        elif case == "lateral":
            add(user, "access", "frontend", when)
            add(user, "access", "secrets", when + rng.randint(10, 50), True)
        elif case == "insider_approved_edge":
            add(user, "access", "frontend", when)
            add(user, "access", "billing", when + rng.randint(10, 50), True)
        elif case == "slow_lateral":
            add(user, "access", "frontend", when)
            add(user, "access", "secrets", when + rng.randint(90, 140), True)
        elif case == "revoked_use":
            add(user, "access", "frontend", when)
            add(user, "access", "frontend", when + 30, True, "denied", {"reason": "revoked device"})
    return sorted(events, key=lambda event: (event["observed_at"], event["id"]))


if __name__ == "__main__":
    fixtures = Path(__file__).resolve().parents[1] / "fixtures"
    fixtures.mkdir(exist_ok=True)
    for name, events in (("labelled_logs.json", make_events()), ("heldout_logs.json", make_heldout_events())):
        (fixtures / name).write_text(json.dumps(events, indent=2) + "\n")
        print(fixtures / name)
