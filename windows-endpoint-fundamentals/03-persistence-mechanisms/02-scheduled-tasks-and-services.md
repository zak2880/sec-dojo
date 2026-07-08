# Scheduled Tasks and Services

- [ ] Read
- [ ] Reviewed KQL example
- [ ] Could explain this to someone else

## Why this matters for detection

Scheduled tasks and services both give an attacker a durable, SYSTEM-capable execution trigger — and both leave a native, hard-to-fully-suppress log entry when created.

## Core concept

- **`schtasks.exe /create`** (or the equivalent Task Scheduler COM API) registers a task that runs on a schedule, at logon, or on an event trigger — a favourite for both persistence and delayed/staged execution.
- **Event ID 7045 — "Service Installed":** new service creation is comparatively rare in normal operation — most services get installed once, at OS or application install time, not continuously during day-to-day use. Any 7045 firing well after initial provisioning deserves a look.
- **Unusual service paths:** legitimate services almost always run from stable, well-known locations (`System32`, `Program Files`). A service `ImagePath` pointing at `Temp`, `AppData`, or `ProgramData` is a strong anomaly — no vendor ships a production service from a user-writable temp directory.
- Both mechanisms can run as **SYSTEM**, which is exactly why they're attractive for privilege-preserving persistence after an initial user-level foothold.

## Diagram

```
schtasks.exe /create /tn "UpdateCheck" /tr "powershell.exe -enc ..." /sc onlogon
                                                        │
                                                        ▼
                                    Runs silently at every logon, indefinitely

Event ID 7045: Service "WinUpdateSvc" installed, ImagePath = C:\Users\Public\svc.exe
                                                        │
                                                        ▼
                                    Runs as SYSTEM from a user-writable path
```

## KQL Example

**Variant A — scheduled task created with a suspicious action:**

```kql
DeviceEvents
| where ActionType == "ScheduledTaskCreated"
| extend TaskAction = tostring(parse_json(AdditionalFields).ActionCommand)
| where TaskAction has_any ("powershell", "cmd.exe", "mshta", "rundll32", "certutil")
       or TaskAction has_any (@"\Temp\", @"\AppData\")
| project Timestamp, DeviceName, InitiatingProcessAccountName, TaskAction
| sort by Timestamp desc
```

**Variant B — new service installed from an unusual path:**

```kql
DeviceEvents
| where ActionType == "ServiceInstalled"
| extend ServiceImagePath = tostring(parse_json(AdditionalFields).ServiceImagePath)
| where ServiceImagePath has_any (@"\Temp\", @"\AppData\", @"\ProgramData\", @"\Users\Public\")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ServiceImagePath
| sort by Timestamp desc
```
