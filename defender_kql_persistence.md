# EDR Hunt Queries — Persistence (Microsoft Defender / Sentinel KQL)

Queries target Microsoft Defender for Endpoint / Sentinel Advanced Hunting schema. Tune time ranges and exclusions to your environment.

## T1547.001 — Registry Run / RunOnce Keys
```kql
DeviceRegistryEvents
| where ActionType in ("RegistryValueSet","RegistryKeyCreated")
| where RegistryKey has_any (
    @"CurrentVersion\Run",
    @"CurrentVersion\RunOnce")
| where RegistryValueData !startswith @"C:\Program Files"
| project Timestamp, DeviceName, InitiatingProcessAccountName,
          RegistryKey, RegistryValueName, RegistryValueData,
          InitiatingProcessFileName
| order by Timestamp desc
```

## T1053.005 — Scheduled Tasks
```kql
DeviceProcessEvents
| where FileName =~ "schtasks.exe"
| where ProcessCommandLine has "/create"
| where ProcessCommandLine has_any ("\\Temp\\","\\AppData\\","Users\\Public")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine,
          InitiatingProcessFileName
| order by Timestamp desc
```
Pair with the registration log:
```kql
DeviceEvents
| where ActionType == "ScheduledTaskCreated"
| project Timestamp, DeviceName, AdditionalFields
```

## T1543.003 — Windows Services
```kql
DeviceEvents
| where ActionType == "ServiceInstalled"
| extend Img = tostring(parse_json(AdditionalFields).ServiceImagePath)
| where Img has_any ("\\Temp\\","\\AppData\\","\\Users\\Public","\\ProgramData\\")
| project Timestamp, DeviceName, Img, AdditionalFields
| order by Timestamp desc
```

## T1547.001 — Startup Folder
```kql
DeviceFileEvents
| where FolderPath has @"Start Menu\Programs\Startup"
| where ActionType == "FileCreated"
| project Timestamp, DeviceName, InitiatingProcessAccountName,
          FileName, FolderPath, InitiatingProcessFileName
| order by Timestamp desc
```

## Cross-mechanism baseline sweep
```kql
DeviceRegistryEvents
| where RegistryKey has_any (@"CurrentVersion\Run", @"Services")
| summarize count() by DeviceName, RegistryKey, RegistryValueName
```
