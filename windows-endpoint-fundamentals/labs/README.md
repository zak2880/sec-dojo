# Labs

Hands-on exercises that reinforce the sec-dojo lessons using a Windows lab VM.

## Prerequisites

- A **Windows 10/11 or Server** lab VM (isolated — snapshot before running anything malicious-adjacent)
- **Sysmon** installed with the [SwiftOnSecurity config](https://github.com/SwiftOnSecurity/sysmon-config) (or similar)
- **Event Viewer** access, or events forwarded to a SIEM/Sentinel workspace for KQL querying
- Local admin rights on the lab VM (some tasks require enabling non-default audit policies)

## How labs work

Each lab has:
1. **Objective** — what you're trying to observe or detect
2. **Setup** — how to generate the activity
3. **Task** — what to find, with hints for Event Viewer/KQL
4. **Verify** — how to confirm you got the right answer

---

## Lab 01 — Sysmon Event ID 1 for LOLBin Execution

**Linked lesson:** [Living-off-the-Land Binaries](../01-process-fundamentals/03-living-off-the-land-binaries.md) · [Sysmon Event IDs Overview](../02-sysmon-and-event-logs/01-sysmon-event-ids-overview.md)

### Objective

Trigger a Sysmon Event ID 1 for a classic LOLBin technique and identify the anomalous parent-child relationship.

### Setup

On the lab VM, simulate a LOLBin download-and-decode from a shell (use a harmless test payload, not live malware):

```powershell
# From a cmd.exe or PowerShell prompt:
certutil.exe -urlcache -f https://example.com/robots.txt out.txt
certutil.exe -decode out.txt out.decoded
```

### Task

Open Event Viewer and browse to **Applications and Services Logs → Microsoft → Windows → Sysmon → Operational**. Find the Event ID 1 entries for `certutil.exe`.

**Find:** What is the `ParentImage` for this `certutil.exe` process? Is `cmd.exe`/`powershell.exe` spawning `certutil.exe` interactively itself worth noting, or is it the certutil command-line arguments that carry the real signal here?

### Verify

You should see two Event ID 1 entries with `Image = C:\Windows\System32\certutil.exe` and a `CommandLine` field containing `-urlcache` and `-decode` — the arguments, not the parent, are what make this LOLBin usage rather than a routine certificate operation.

---

## Lab 02 — Comparing 4688 and Sysmon Event ID 1 for the Same Process

**Linked lesson:** [Windows Security Event Essentials](../02-sysmon-and-event-logs/02-windows-security-event-essentials.md) · [Sysmon Event IDs Overview](../02-sysmon-and-event-logs/01-sysmon-event-ids-overview.md)

### Objective

Review a native Event ID 4688 and a Sysmon Event ID 1 for the *same* process creation, and compare what each captures.

### Setup

Enable process creation auditing and command-line logging (both non-default):

```powershell
# Enable process creation auditing
auditpol /set /subcategory:"Process Creation" /success:enable

# Enable command-line capture in 4688 events (registry)
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" `
  -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1 -PropertyType DWord -Force

# Trigger a process creation to capture
notepad.exe C:\Windows\System32\drivers\etc\hosts
```

### Task

Find both log entries for the `notepad.exe` launch:
- **Security log**, Event ID **4688**
- **Sysmon Operational log**, Event ID **1**

**Find:** List every field present in the Sysmon event that is *absent* from the 4688 event (hint: look for hashes, integrity level, and `OriginalFileName`).

### Verify

The 4688 event gives you `NewProcessName`, `CommandLine` (only with the registry key above), `ParentProcessName`, and the account — but no file hash, no integrity level, and no `OriginalFileName`. The Sysmon Event ID 1 for the same launch includes all of the above by default, which is exactly why Sysmon is preferred wherever it can be deployed, even though native auditing is what you'll always have as a fallback.

---

## Planned labs *(coming soon)*

| Lab | Topic | Tools |
|---|---|---|
| Lab 03 | Registry Run key persistence — plant and detect | Registry Editor + Sysmon Event ID 13 |
| Lab 04 | Scheduled task persistence — Event ID 7045 review | Task Scheduler + Security log |
| Lab 05 | PowerShell obfuscation — encode and detect `-EncodedCommand` | PowerShell + DeviceProcessEvents / 4104 |
| Lab 06 | Simulated LSASS access pattern review | Sysmon Event ID 10 (ProcessAccess) |
