# Sysmon Event IDs Overview

- [ ] Read
- [ ] Reviewed KQL example
- [ ] Could explain this to someone else

## Why this matters for detection

Sysmon turns Windows from "barely logs anything useful" into a rich, structured telemetry source — five Event IDs cover the large majority of what you'll actually query day-to-day.

## Core concept

- **Event ID 1 — Process Creation:** the single richest event Sysmon produces — full command line, hashes, parent process, and integrity level. This is the backbone of almost every process-based detection in this module.
- **Event ID 3 — Network Connection:** logs outbound TCP/UDP connections *with the initiating process attached*, something the Windows Firewall log alone doesn't give you.
- **Event ID 7 — Image Loaded:** records DLLs loaded into a process — useful for catching unsigned or unexpected DLLs loaded into sensitive processes (ties into injection detection).
- **Event ID 11 — File Created:** logs new file creation, including hash — catches dropped payloads, staged tools, and persistence artefacts (e.g. a new file appearing in the Startup folder).
- **Event ID 13 — Registry Value Set:** logs a value being written to the registry — the primary way to catch Run-key and other registry-based persistence as it happens.

> ⚠️ **Caveat:** None of this exists without **Sysmon installed** and its events forwarded into your SIEM (e.g. via the `Event` table with `Source == "Microsoft-Windows-Sysmon"`). It is not part of a default Windows install.

## Diagram

```
Event ID 1  → Process Creation     (who ran what, with what parent)
Event ID 3  → Network Connection   (which process talked to where)
Event ID 7  → Image Loaded         (which DLLs loaded into which process)
Event ID 11 → File Created         (what got dropped on disk)
Event ID 13 → Registry Value Set   (what got written for persistence)
```

## KQL Example

**Variant A — Sysmon Event ID 1, process creation from a Temp-like path:**

```kql
Event
| where Source == "Microsoft-Windows-Sysmon"
| where EventID == 1
| extend EventData = parse_xml(EventData)
| extend Image = tostring(EventData.DataItem.EventData.Data[4].["#text"])
| where Image has_any (@"\AppData\Local\Temp", @"\Windows\Temp", @"\ProgramData")
| project TimeGenerated, Computer, Image
| sort by TimeGenerated desc
```

**Variant B — Sysmon Event ID 11, file created in the Startup folder:**

Event ID 1 catches execution; Event ID 11 catches the persistence artefact being written in the first place, often *before* it ever runs — useful as an earlier-stage tripwire:

```kql
Event
| where Source == "Microsoft-Windows-Sysmon"
| where EventID == 11
| extend EventData = parse_xml(EventData)
| extend TargetFilename = tostring(EventData.DataItem.EventData.Data[4].["#text"])
| where TargetFilename has @"\Start Menu\Programs\Startup"
| project TimeGenerated, Computer, TargetFilename
| sort by TimeGenerated desc
```
