# PersistentPelican — Companion Detection Content

Blue-team material to accompany the PersistentPelican lab. Use it to detect, hunt, and remediate the persistence techniques the toolkit exercises.

## Contents
- `sigma/` — Sigma detection rules, one file per ATT&CK technique (Windows, Linux, macOS).
- `edr/defender_kql_persistence.md` — Microsoft Defender / Sentinel advanced hunting queries.
- `edr/osquery_persistence_packs.md` — cross-platform osquery host-state queries for baselining and diffing.
- `REMEDIATION_CHECKLIST.md` — student worksheet: find, remove, verify.

## How to use in a lab
1. Baseline the host (osquery sweep + autoruns/services/cron/systemd/launchd snapshots).
2. Deploy detection rules to your SIEM/EDR.
3. Run the toolkit in the isolated lab.
4. Hunt: identify every mechanism using the Sigma/EDR/osquery content.
5. Remediate using the checklist; verify each removal.
6. Tune rules until every technique reliably fires, then reboot and re-verify.

All content is for authorized, isolated lab use. Detection logic is starting-point quality — validate and tune against your own telemetry before relying on it.
