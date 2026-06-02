# osquery Host-State Queries — Persistence (cross-platform)

Use these to enumerate live persistence state for baselining and post-run comparison. Diff results against a clean baseline; anything new is a candidate.

## Windows

Autorun entries (Run keys, services, scheduled tasks, startup):
```sql
SELECT name, path, source, status FROM autoexec;
```
Services with binaries in suspicious paths:
```sql
SELECT name, display_name, path, start_type, status
FROM services
WHERE path LIKE '%\Temp\%'
   OR path LIKE '%\AppData\%'
   OR path LIKE '%\ProgramData\%';
```
Scheduled tasks:
```sql
SELECT name, action, path, enabled, hidden FROM scheduled_tasks
WHERE enabled = 1;
```

## Linux

Cron (system + user):
```sql
SELECT command, path, event, minute, hour FROM crontab;
```
Startup/systemd items:
```sql
SELECT name, path, status, source, type FROM startup_items;
```
Shell init files (hash/track for change):
```sql
SELECT path, mtime, size FROM file
WHERE path IN ('/etc/profile','/root/.bashrc')
   OR path LIKE '/home/%/.bashrc'
   OR path LIKE '/home/%/.profile';
```

## macOS

Launch agents / daemons:
```sql
SELECT name, path, program, run_at_load, keep_alive
FROM launchd
WHERE path LIKE '%LaunchAgents%'
   OR path LIKE '%LaunchDaemons%';
```
Login items + startup:
```sql
SELECT name, path, source, status, type FROM startup_items;
```

## Workflow
1. Capture baseline: run each query, save output.
2. Run the toolkit in the lab.
3. Re-run queries, diff against baseline.
4. Every new row maps to a technique in the README — identify and remediate it.
