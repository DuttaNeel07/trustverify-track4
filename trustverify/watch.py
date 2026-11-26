"""Live detection and response over the verified authority log.

Each poll exports the log, verifies it against the pinned trust root and retained
checkpoint, runs the explainable detector, and records every new alert with its
detection latency. With responses enabled, a separate administrator identity contains
the alert through an ordinary signed, audited request:

- unapproved_privilege_grant / self_approved_grant: remove the granted service permission
- unexpected_service_transition: remove the identity's permission for the destination service
- revoked_credential_use: no action; the authority already denied it

Responses are themselves audit events, so operators can review and reverse them.
"""

import json
import time
from pathlib import Path

from .authority import Denied, verify_log
from .detector import analyze
from .encoding import canonical

CONTAINMENT = {"unapproved_privilege_grant": "remove_permission",
               "self_approved_grant": "remove_permission",
               "unexpected_service_transition": "remove_permission"}


class Watcher:
    def __init__(self, authority, responder=None, output=None, clock=time.time):
        self.authority, self.responder, self.clock = authority, responder, clock
        self.output = Path(output) if output else None
        self.seen = set()
        self.alerts = []

    def _respond(self, alert):
        action = CONTAINMENT.get(alert["rule"])
        if action is None:
            return {"action": "none", "reason": "authority already denied the request"}
        if self.responder is None:
            return {"action": "none", "reason": "responses disabled"}
        service = alert["services"][-1]
        try:
            self.responder.call(action, owner=alert["identity"], service=service)
            return {"action": action, "owner": alert["identity"], "service": service, "status": "applied"}
        except (Denied, ValueError) as exc:
            return {"action": action, "owner": alert["identity"], "service": service,
                    "status": "failed", "reason": str(exc)}

    def poll(self):
        exported = self.authority.export_log()
        verify_log(exported["records"], self.authority.trust, exported["checkpoint"])
        bodies = [r["body"] for r in exported["records"]]
        observed = {b["seq"]: b["observed_at"] for b in bodies}
        new = []
        for alert in analyze(bodies)["alerts"]:
            key = (alert["rule"], alert["event_id"])
            if key in self.seen:
                continue
            self.seen.add(key)
            detected = self.clock()
            record = {**alert, "detected_at": detected,
                      "detection_latency_seconds": detected - observed[alert["event_id"]]}
            record["response"] = self._respond(alert)
            new.append(record)
        if new and self.output:
            self.output.parent.mkdir(parents=True, exist_ok=True)
            with self.output.open("ab") as stream:
                for record in new:
                    stream.write(canonical(record) + b"\n")
        self.alerts.extend(new)
        return new

    def run(self, interval=1.0, once=False, progress=print):
        while True:
            for record in self.poll():
                progress(json.dumps({"rule": record["rule"], "identity": record["identity"],
                                     "events": record["events"], "response": record["response"],
                                     "detection_latency_seconds": round(record["detection_latency_seconds"], 3)}))
            if once:
                return self.alerts
            time.sleep(interval)
