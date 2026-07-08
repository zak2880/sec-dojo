# Process Basics and Trees

- [ ] Read
- [ ] Reviewed KQL example
- [ ] Could explain this to someone else

## Why this matters for detection

Almost every endpoint detection ultimately reduces to "was this a plausible parent for that child?" — the process tree is the cheapest, highest-signal artefact you have.

## Core concept

- Every process has a **PID** and records its parent's PID (**PPID**) at creation time. Windows doesn't cryptographically bind this link, so PPID spoofing exists — but treat any unusual lineage as signal regardless of whether it was spoofed.
- **Normal chain:** `explorer.exe` (shell) → `outlook.exe` (user opens mail client) → `winword.exe` (user opens an attachment). Each hop is a plausible, expected human action.
- **Top-tier detection signal:** Office apps (`winword.exe`, `excel.exe`, `outlook.exe`) spawning `cmd.exe`, `powershell.exe`, `wscript.exe`, or `mshta.exe` — the near-universal pattern for macro and exploit-based execution.
- Other suspicious lineages: `services.exe` spawning `cmd.exe` directly, `svchost.exe` spawning `powershell.exe`, or anything spawning as a child of `lsass.exe`.
- "Normal" varies by environment — baseline your own fleet before tuning thresholds; some orgs run PowerShell constantly for legitimate admin tooling.

## Diagram

```
Normal:
  explorer.exe → outlook.exe → winword.exe            (expected human chain)

Suspicious:
  winword.exe → powershell.exe → (network connection)  (macro → shell → C2)
  services.exe → cmd.exe                                (unexpected service child)
```

## KQL Example

**Variant A — Office apps spawning a shell (broad):**

Flag the classic macro/exploit execution pattern:

```kql
DeviceProcessEvents
| where InitiatingProcessFileName in~ ("winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe")
| where FileName in~ ("cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine
| sort by Timestamp desc
```

**Variant B — unexpected shell parents, tuned:**

The broad query above misses shells spawned by other unusual parents and doesn't account for legitimate automation. Widen the parent list and exclude known-benign automation accounts/paths to cut noise:

```kql
DeviceProcessEvents
| where FileName in~ ("cmd.exe", "powershell.exe", "pwsh.exe")
| where InitiatingProcessFileName in~ ("winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "services.exe", "svchost.exe")
| where InitiatingProcessFolderPath !has @"\Program Files\"   // exclude known third-party automation installed under Program Files
| where AccountName !endswith "$"                              // exclude machine/service accounts running scheduled automation
| summarize FirstSeen = min(Timestamp), Count = count()
  by DeviceName, AccountName, InitiatingProcessFileName, FileName
| sort by FirstSeen desc
```
