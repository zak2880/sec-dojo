# Registry Run Keys and Startup Folder

- [ ] Read
- [ ] Reviewed KQL example
- [ ] Could explain this to someone else

## Why this matters for detection

Run keys are the oldest persistence trick in the book — and still one of the most common, because they work, require no special privileges from `HKCU`, and blend in among dozens of legitimate startup entries.

## Core concept

- **`HKCU\...\Run` / `HKLM\...\Run`:** any value written here launches automatically at logon (`HKCU`) or boot (`HKLM`, needs admin). `HKCU` is especially attractive to attackers — no elevation needed.
- **`RunOnce`:** same mechanism, but Windows deletes the value after it executes once — useful for staged/multi-step installers, legitimate and malicious alike.
- **Startup folder:** `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` (per-user) and its `%ProgramData%` equivalent (all-users). Dropping a shortcut or script here achieves the same effect without touching the registry at all.
- **Why still common despite being well-known:** it's simple, reliable across Windows versions, and a real endpoint typically has 10–30 legitimate Run entries (printer helpers, VPN clients, update agents) — an attacker's entry has to actually stand out against that noise, which requires baselining, not just "does a Run key exist."

## Diagram

```
HKCU\Software\Microsoft\Windows\CurrentVersion\Run
  "UpdateHelper" = "C:\Users\bob\AppData\Roaming\svc.exe"   ← blends in with legit entries

%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\
  invoice.lnk → powershell.exe -enc ...                     ← startup-folder equivalent
```

## KQL Example

**Variant A — Run/RunOnce key writes pointing at an unusual location:**

```kql
DeviceRegistryEvents
| where ActionType == "RegistryValueSet"
| where RegistryKey has_any (@"\CurrentVersion\Run", @"\CurrentVersion\RunOnce")
| where RegistryValueData has_any (@"\AppData\", @"\Temp\", @"\ProgramData\")
| project Timestamp, DeviceName, InitiatingProcessAccountName, RegistryKey, RegistryValueName, RegistryValueData
| sort by Timestamp desc
```

**Variant B — new file dropped directly in the Startup folder:**

```kql
DeviceFileEvents
| where ActionType == "FileCreated"
| where FolderPath has @"\Start Menu\Programs\Startup"
| project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, FolderPath, SHA256
| sort by Timestamp desc
```
