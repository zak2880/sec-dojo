# Process Injection Basics

- [ ] Read
- [ ] Reviewed KQL example
- [ ] Could explain this to someone else

## Why this matters for detection

Injection lets malware run inside a trusted process's memory space — the malicious code never appears as its own process, so process-name allowlisting and casual "what's running" checks miss it entirely.

## Core concept

- **DLL injection:** the attacker forces a target process to load a malicious DLL, classically via `CreateRemoteThread` + `LoadLibrary`, or **reflective DLL injection**, which loads the DLL directly from memory without it ever touching disk.
- **Process hollowing:** the attacker starts a legitimate process suspended, unmaps its real memory image, and writes malicious code in its place before resuming — the process looks legitimate (right name, right PID, right parent) but the code executing is not what was launched.
- **Why attackers use it:** evade AV/allowlisting that trusts signed, known binaries; hide C2 network traffic behind a trusted process name (e.g. beaconing that appears to come from `svchost.exe`); blend into normal process lists.
- **Telemetry signs:** unusual cross-process memory operations (`VirtualAllocEx`/`WriteProcessMemory` targeting another process), a process's on-disk image not matching what's actually mapped in memory (hollowing), and high-privilege handles opened to sensitive process names by unexpected callers.

> ⚠️ **Caveat:** Rich cross-process memory-access telemetry isn't captured by MDE's default sensor. The **"Block process injection" Attack Surface Reduction (ASR) rule** must be enabled (audit or block mode) to get native `DeviceEvents` records — it's off by default.

## Diagram

```
Process hollowing:
  1. Launch legit.exe SUSPENDED
  2. Unmap legit.exe's real memory image
  3. Write malicious code into the hollowed space
  4. Resume thread → "legit.exe" is now running attacker code
```

## KQL Example

**Variant A — ASR-based injection detection (requires ASR rule enabled):**

```kql
DeviceEvents
| where ActionType in ("AsrProcessInjectionAudited", "AsrProcessInjectionBlocked")
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, ActionType, FileName
| sort by Timestamp desc
```

**Variant B — unsigned/uncommon DLL loaded into a sensitive process (no ASR dependency):**

Without the ASR rule enabled, pivot on `DeviceImageLoadEvents` instead — a DLL loading into a highly sensitive process from an unusual folder is a reasonable fallback signal:

```kql
DeviceImageLoadEvents
| where InitiatingProcessFileName in~ ("lsass.exe", "svchost.exe", "explorer.exe", "winlogon.exe")
| where FolderPath !startswith @"C:\Windows\System32" and FolderPath !startswith @"C:\Windows\SysWOW64"
| project Timestamp, DeviceName, InitiatingProcessFileName, FileName, FolderPath, SHA256
| sort by Timestamp desc
```
