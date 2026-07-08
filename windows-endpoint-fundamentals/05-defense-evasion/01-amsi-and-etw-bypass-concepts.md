# AMSI and ETW Bypass Concepts

- [ ] Read
- [ ] Reviewed KQL example
- [ ] Could explain this to someone else

## Why this matters for detection

The bypass attempt itself is a rarer, more stable signal than whatever payload follows it — payloads morph constantly, the patching technique barely does.

## Core concept

- **AMSI (Antimalware Scan Interface):** a Windows API that lets scripting engines (PowerShell, VBA, JScript) submit content to the registered AV/EDR for scanning *before* it executes — the interception point most in-memory/"fileless" scripts have to pass through.
- **ETW (Event Tracing for Windows):** the OS-wide logging framework EDR products subscribe to for real-time telemetry. Much of what ultimately populates tables like `DeviceProcessEvents` originates from ETW providers.
- **How attackers bypass both:** an in-memory patch to the current process, applied at runtime. For AMSI, overwriting `AmsiScanBuffer` in `amsi.dll` so it always returns "clean" without actually scanning. For ETW, patching `EtwEventWrite` in `ntdll.dll` to silently return without emitting the event. Neither is persistent — it's reapplied every session.
- **Why detect the attempt, not just the payload:** the memory-patch action itself — a script writing to its own loaded copy of `ntdll.dll`/`amsi.dll` — is a rare, narrow behaviour almost no legitimate script performs. That's more durable to detect than trying to catch every payload that gets through afterward.

## Diagram

```
Normal:    PowerShell script → AmsiScanBuffer() → AV/EDR inspects content → allow/block
Bypassed:  PowerShell script → AmsiScanBuffer() patched to return "clean" → content unscanned
                                        │
                                        ▼
                    The PATCH ITSELF is the detectable, stable signal
```

## KQL Example

**Variant A — native AMSI detection signal (the win case, when AMSI wasn't bypassed):**

```kql
DeviceEvents
| where ActionType == "AmsiTriggered"
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName
| sort by Timestamp desc
```

**Variant B — lexical AMSI/ETW bypass indicators (catches attempts even if AMSI itself was defeated):**

Variant A relies on AMSI still working; a successful bypass produces no `AmsiTriggered` event at all. Flag the bypass code pattern itself instead:

```kql
DeviceProcessEvents
| where FileName in~ ("powershell.exe", "pwsh.exe")
| where ProcessCommandLine has_any (
    "amsiutils", "amsiInitFailed", "AmsiScanBuffer",
    "EtwEventWrite", "VirtualProtect"
  )
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
| sort by Timestamp desc
```
