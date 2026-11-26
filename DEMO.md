# Five-minute walkthrough

This is the recording script. After recording, put the public unlisted link in `submission.json` and run `python scripts/build_brief.py`.

Prepare with `python -m pytest -q`. Keep the README, terminal, `reports/demo.json`, `reports/detector.json` and PDF ready. Use fresh synthetic data only. For an interrupted recording, choose a new demo directory.

| Time | What to show and say |
|---|---|
| 0:00–0:40 | Run `python ../Track-4-Toolkit/validate.py --entry track4_service.py` and show it pass with only pqcrypto installed. State the problem and USP. Show the architecture: two logical endpoints, three mock service processes, one shared authority. Explicitly distinguish this from a replicated deployment. |
| 0:40–1:30 | Run `python -m trustverify demo --directory runtime/recording`. Explain the fresh ML-DSA identities, library hybrid HPKE and endpoint-held one-use recipient secret. Open the resulting `report.json`. |
| 1:30–2:15 | Show `rotation_old_key_rejected_all_nodes` and `rotation_transfer_continues`. State zero new-admission grace and the bounded 120-second continuation exception. Show recovered loss/reordering, replay and changed-recipient rejection. |
| 2:15–3:00 | Show revocation observations for all nodes, re-enrolment and unaffected Bob access. Explain the single monotonic harness clock and that measured rejection times are probe upper bounds. Show staged versus committed process-crash recovery and preserved revocation/data. |
| 3:00–3:40 | Show corrupted-backup failure and verified restore. Run the README's `verify` command using independent trust/checkpoint files. Explain why a stale valid backup and a truncated acknowledged log suffix are refused. Show the injected newline remains inside one Alice event. |
| 3:40–4:30 | Open `alerts.json`: unapproved grant to Carol, followed by `frontend -> secrets` using valid credentials. Point to identity, service path, event IDs and explanation. Show `self_approved_grant_rejected` in the report. Run `python -m trustverify practice --toolkit ../Track-4-Toolkit/practice`; show the role-change and lateral-sequence alerts. Contrast rule-aligned F1 1.0 with the held-out 0.78 and its known misses. |
| 4:30–5:00 | Show the two-page PDF and threat model. State clock bounds, uncertain-order notices, central fail-closed availability, no resumption, no production assurance and no ability to retract copied plaintext. Finish with the clean-machine commands and test results. |

For a failed live demo, the final submission requires an actual publicly accessible five-minute video URL in `submission.json`, followed by `python scripts/build_brief.py`.
