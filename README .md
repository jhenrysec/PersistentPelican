# PersistentPelican

A blue-team teaching artifact for the **detection and remediation** of common persistence techniques, mapped to MITRE ATT&CK Persistence (TA0003). PersistentPelican exercises a set of cross-platform persistence mechanisms so defenders can build, validate, and tune detections against known adversary behavior.

> ⚠️ **Authorized lab use only.** This toolkit establishes persistence mechanisms on a host. Run it exclusively on systems you own or are explicitly authorized to test, on an isolated lab network — never on production, shared, or third-party systems. This README intentionally documents **detection and remediation** rather than deployment.

## Purpose

The goal is defensive. Each technique the toolkit exercises is paired here with:

- **What it looks like** — the artifacts and behavior it produces on the host
- **How to detect it** — data sources, telemetry, and hunt ideas
- **How to remediate it** — how to identify and remove the persistence

This lets students and SOC/DFIR analysts practice finding and removing persistence against a known ground truth, then validate that their detections actually fire.

## Scope

PersistentPelican covers persistence across Linux, macOS, and Windows. The platform logic lives in `linux.go`, `windows.go`, and `cross.go`, with shared types and reporting in `types.go`, `helpers.go`, and `report.go`. The accompanying `Persistence_Toolkit_Guide.docx` contains the full instructional walkthrough.

## Technique Coverage and Detection Guidance

The mappings below reflect standard, well-documented ATT&CK persistence techniques. Confirm against your build and adjust as needed.

### Windows

**Registry Run / RunOnce keys — T1547.001**
- *Artifacts:* new values under `HKLM\...\CurrentVersion\Run`, `RunOnce`, and the per-user `HKCU` equivalents.
- *Detect:* monitor registry-modification events (Sysmon Event ID 13, Security 4657) on autorun keys; baseline expected autoruns and alert on deltas. Autoruns/autorunsc is useful for triage.
- *Remediate:* remove the offending value; trace the referenced binary/script and remove it.

**Scheduled Task — T1053.005**
- *Artifacts:* new task in `\Windows\System32\Tasks\`, registration in the registry.
- *Detect:* Security Event ID 4698 (task created), 4702 (updated); Sysmon process creation showing `schtasks.exe` or `svchost` spawning unexpected children. Hunt for tasks with unusual triggers or LOLBin actions.
- *Remediate:* delete the task and its referenced payload.

**Windows Service — T1543.003**
- *Artifacts:* new service entries under `HKLM\SYSTEM\CurrentControlSet\Services`.
- *Detect:* Security Event ID 7045 (new service installed), 4697; alert on services with binaries in user-writable or temp paths.
- *Remediate:* stop and delete the service, remove the binary.

**Startup Folder — T1547.001**
- *Artifacts:* files dropped into per-user or common Startup folders.
- *Detect:* file-creation monitoring (Sysmon Event ID 11) on Startup paths.
- *Remediate:* remove the dropped file.

### Linux

**Cron Jobs — T1053.003**
- *Artifacts:* new entries in user crontabs, `/etc/crontab`, `/etc/cron.d/`, `/etc/cron.*/`.
- *Detect:* file-integrity monitoring on cron paths; auditd watches; hunt for cron entries invoking interpreters, network tools, or scripts in `/tmp`.
- *Remediate:* remove the cron entry and the referenced script.

**Systemd Service / Timer — T1543.002**
- *Artifacts:* unit files in `/etc/systemd/system/`, `~/.config/systemd/user/`, or `/lib/systemd/system/`; enabled timers.
- *Detect:* FIM on systemd unit directories; `systemctl list-unit-files` / `list-timers` diffing against a baseline; auditd on unit-file writes.
- *Remediate:* disable and remove the unit/timer, reload the daemon.

**Shell Profile / RC Modification — T1546.004**
- *Artifacts:* appended lines in `~/.bashrc`, `~/.bash_profile`, `~/.profile`, `/etc/profile.d/`.
- *Detect:* FIM on shell init files; diff against baseline; hunt for command substitutions or curl/wget invocations in profile scripts.
- *Remediate:* revert the file to a known-good state.

### macOS

**Launch Agents / Launch Daemons — T1543.001 / T1543.004**
- *Artifacts:* plist files in `~/Library/LaunchAgents/`, `/Library/LaunchAgents/`, `/Library/LaunchDaemons/`.
- *Detect:* FIM on LaunchAgent/Daemon directories; Endpoint Security framework file events; review `launchctl list` against a baseline.
- *Remediate:* unload with `launchctl`, remove the plist and referenced program.

**Login Items / Profile — T1547.011 / T1546**
- *Artifacts:* added login items, shell profile modifications analogous to Linux.
- *Detect:* monitor login-item configuration and shell init files.
- *Remediate:* remove the login item / revert the profile.

## Suggested Defensive Workflow

1. **Baseline** the lab host (autoruns, services, scheduled tasks/cron/systemd, launch items, shell profiles).
2. Run the toolkit in the lab to establish persistence.
3. **Hunt** using the data sources above and try to identify every mechanism installed.
4. Compare findings against the ground truth in `Persistence_Toolkit_Guide.docx`.
5. **Remediate** and confirm the host is clean.
6. Tune detections (Sigma rules, EDR queries, FIM watch lists) until each technique reliably fires.

## Recommended Telemetry

- **Windows:** Sysmon (config tuned for registry, file, process, and service events), Windows Security/System event logs.
- **Linux:** auditd, FIM (AIDE/Wazuh), systemd journal.
- **macOS:** Endpoint Security framework tooling, unified logs, FIM.

## Educational Use

This project exists to teach defenders how persistence works so they can detect and remove it. It is intended for cybersecurity training, DFIR practice, and detection engineering in controlled, authorized lab environments. The author assumes no liability for misuse.

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

## License

MIT — see [LICENSE](LICENSE).
