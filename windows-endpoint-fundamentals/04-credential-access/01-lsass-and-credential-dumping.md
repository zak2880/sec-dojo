# LSASS and Credential Dumping

- [ ] Read
- [ ] Reviewed KQL example
- [ ] Could explain this to someone else

## Why this matters for detection

LSASS is the single highest-value memory target on any Windows host — dump it once and you potentially get every credential of every account with an active session, not just the one you started with.

## Core concept

- **LSASS (Local Security Authority Subsystem Service)** holds credential material in memory for logged-on users — NTLM hashes, Kerberos tickets, and (if WDigest is enabled) plaintext passwords. Dumping it and cracking/replaying the contents grants access to every account with a live session on that box.
- **Process access patterns:** the list of legitimate processes that ever need a high-privilege handle (`PROCESS_VM_READ`/`PROCESS_QUERY_INFORMATION`) to `lsass.exe` is short and well-known. A browser, Office app, or random binary from `Temp` requesting that kind of access to `lsass.exe` is one of the highest-fidelity signals available on an endpoint.
- **Mimikatz-style signatures:** the `sekurlsa` module's characteristic access mask, and the **`comsvcs.dll` MiniDump technique** (`rundll32.exe comsvcs.dll, MiniDump <lsass PID> out.dmp full`) — a LOLBin-based alternative to running Mimikatz directly, dumping LSASS with a signed Microsoft DLL.

> ⚠️ **Caveat:** Full process-access telemetry (the actual `GrantedAccess` mask against `lsass.exe`) is best captured via the **"Block credential stealing from LSASS" ASR rule** (audit or block mode) — native `DeviceEvents` records depend on it being enabled, which it isn't by default.

## Diagram

```
Normal:     wininit.exe → lsass.exe  (spawns once at boot, no further high-access callers)
Suspicious: chrome.exe  → OpenProcess(lsass.exe, PROCESS_VM_READ)   ← never legitimate
            rundll32.exe comsvcs.dll, MiniDump <PID> out.dmp full  ← LOLBin dump technique
```

## KQL Example

**Variant A — ASR-based LSASS credential theft detection (requires ASR rule enabled):**

```kql
DeviceEvents
| where ActionType in ("AsrLsassCredentialTheftAudited", "AsrLsassCredentialTheftBlocked")
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessAccountName
| sort by Timestamp desc
```

**Variant B — comsvcs.dll MiniDump technique (no ASR dependency, works out of the box):**

```kql
DeviceProcessEvents
| where FileName =~ "rundll32.exe"
| where ProcessCommandLine has "comsvcs.dll" and ProcessCommandLine has "MiniDump"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
| sort by Timestamp desc
```
