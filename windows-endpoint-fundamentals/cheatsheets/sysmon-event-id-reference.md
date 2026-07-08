# Sysmon Event ID Reference

| Event ID | What it captures | Why it matters for detection |
|---|---|---|
| 1 | Process Creation | The richest event Sysmon produces — full command line, hashes, parent process, integrity level. Backbone of process-based detection. |
| 2 | File Creation Time Changed | A process changed a file's creation timestamp — the direct signal for timestomping. |
| 3 | Network Connection | Outbound TCP/UDP connection *with the initiating process attached* — Windows Firewall logging alone doesn't give you this. |
| 5 | Process Terminated | Marks the end of a process's lifetime — useful for building accurate process duration/dwell-time analysis. |
| 6 | Driver Loaded | A kernel driver was loaded — relevant for detecting vulnerable/malicious driver abuse ("BYOVD" attacks). |
| 7 | Image Loaded | DLLs loaded into a process — catches unsigned/unexpected DLLs loaded into sensitive processes (ties into injection detection). |
| 8 | CreateRemoteThread | A process created a thread in another process — a classic DLL/code injection primitive. |
| 10 | ProcessAccess | A process opened a handle to another process — the event that catches LSASS access attempts. |
| 11 | File Created | New file creation, including hash — catches dropped payloads and persistence artefacts (e.g. Startup folder writes). |
| 12/13/14 | Registry Object Added/Deleted / Value Set / Key Renamed | Registry activity — Event ID 13 (Value Set) is the primary way to catch Run-key persistence as it happens. |
| 15 | File Create Stream Hash | A file was written to an NTFS Alternate Data Stream — a common technique for hiding payloads. |
| 17/18 | Pipe Created / Pipe Connected | Named pipe activity — relevant for detecting some C2 frameworks' inter-process communication. |
| 19/20/21 | WMI Event Filter / Consumer / Filter-to-Consumer Binding | The three components of a WMI event subscription — direct visibility into WMI-based persistence being registered. |
| 22 | DNS Query | DNS resolution requests tied to the requesting process — useful for correlating C2 domain lookups back to the responsible binary. |
| 23 | File Delete (archived) | A file was deleted, with Sysmon keeping an archived copy — helps recover payloads an attacker tried to clean up. |
| 25 | Process Tampering | Detects image change or "herpaderping" — a process's on-disk/in-memory image being manipulated after launch, a hollowing indicator. |

> Requires **Sysmon installed** with events forwarded into your SIEM — not part of a default Windows install. See [02-sysmon-and-event-logs/01-sysmon-event-ids-overview.md](../02-sysmon-and-event-logs/01-sysmon-event-ids-overview.md).
