# Persistence Remediation & Verification Checklist

A student-facing worksheet. For each mechanism: **find it, remove it, prove it's gone.** Work top to bottom for the target OS. Do not mark a row complete until the verification step returns clean.

---

## Windows

### T1547.001 — Run / RunOnce Keys
- [ ] **Find:** `reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run"` and the `HKLM` + `RunOnce` equivalents. Compare against baseline.
- [ ] **Remove:** delete the rogue value; locate and delete the referenced binary/script.
- [ ] **Verify:** re-query the key — rogue value absent; referenced file no longer on disk.

### T1053.005 — Scheduled Task
- [ ] **Find:** `schtasks /query /fo LIST /v` (or Task Scheduler) — flag tasks with temp/AppData actions or odd triggers.
- [ ] **Remove:** `schtasks /delete /tn "<TaskName>" /f`; delete the payload.
- [ ] **Verify:** task absent from `schtasks /query`; no leftover file in `\Windows\System32\Tasks\`.

### T1543.003 — Windows Service
- [ ] **Find:** `sc query` / Event ID 7045; flag services with binaries in user-writable paths.
- [ ] **Remove:** `sc stop "<svc>"` then `sc delete "<svc>"`; remove binary.
- [ ] **Verify:** `sc query "<svc>"` returns "does not exist"; binary gone.

### T1547.001 — Startup Folder
- [ ] **Find:** inspect `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` and the common (all-users) path.
- [ ] **Remove:** delete the dropped shortcut/file.
- [ ] **Verify:** folder contains only baseline items.

---

## Linux

### T1053.003 — Cron
- [ ] **Find:** `crontab -l` (per user, incl. root); inspect `/etc/crontab`, `/etc/cron.d/`, `/etc/cron.*`.
- [ ] **Remove:** edit/remove the entry; delete the referenced script.
- [ ] **Verify:** entry absent on re-list; script removed.

### T1543.002 — Systemd
- [ ] **Find:** `systemctl list-unit-files --state=enabled` and `systemctl list-timers`; check `/etc/systemd/system/`, `~/.config/systemd/user/`.
- [ ] **Remove:** `systemctl disable --now <unit>`; delete unit file; `systemctl daemon-reload`.
- [ ] **Verify:** unit no longer listed; `systemctl status <unit>` reports not-found.

### T1546.004 — Shell Profile / RC
- [ ] **Find:** diff `~/.bashrc`, `~/.bash_profile`, `~/.profile`, `/etc/profile.d/*` against baseline.
- [ ] **Remove:** revert the injected lines.
- [ ] **Verify:** file matches known-good baseline (hash compare).

---

## macOS

### T1543.001 / .004 — Launch Agents / Daemons
- [ ] **Find:** list `~/Library/LaunchAgents/`, `/Library/LaunchAgents/`, `/Library/LaunchDaemons/`; review `launchctl list`.
- [ ] **Remove:** `launchctl bootout` / `unload` the job; delete the plist and referenced program.
- [ ] **Verify:** plist gone; job absent from `launchctl list`.

### T1547.011 / T1546 — Login Items / Profile
- [ ] **Find:** check login items and shell init files (as Linux).
- [ ] **Remove:** delete the login item / revert profile.
- [ ] **Verify:** item absent; profile matches baseline.

---

## Final Host Verification
- [ ] Re-run the full osquery baseline sweep — output matches pre-exercise baseline (zero deltas).
- [ ] Re-run EDR hunt queries — no persistence detections in the post-remediation window.
- [ ] All detection rules that fired during the exercise have been reviewed and tuned.
- [ ] Reboot the host and re-verify — nothing re-establishes itself.

**Sign-off:** Host confirmed clean by ______________________  Date ____________
