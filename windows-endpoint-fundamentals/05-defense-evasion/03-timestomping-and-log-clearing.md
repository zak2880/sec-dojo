# Timestomping and Log Clearing

- [ ] Read
- [ ] Reviewed KQL example
- [ ] Could explain this to someone else

## Why this matters for detection

There is essentially no legitimate reason for a normal admin workflow to manually clear an entire event log — when it happens, it should almost always be escalated immediately.

## Core concept

- **Timestomping:** modifying a file's MFT timestamps (the `$STANDARD_INFORMATION` attribute — Created, Modified, Accessed, Entry-Modified, i.e. "MACE") to match legitimate system files', hiding a dropped payload from timeline-based forensic review.
- Basic timestomping only touches `$STANDARD_INFORMATION` (trivially edited via the `SetFileTime` API). The MFT's second timestamp set, `$FILE_NAME`, is often left untouched by simpler tools — a mismatch between the two is a classic forensic tell, but it requires offline MFT parsing, not something logged live.
- **Event ID 1102 (Security log cleared)** and **Event ID 104 (System/Application log cleared)** are extremely high-fidelity: retention-based log rollover happens automatically via policy, it doesn't require a manual "clear log" action. When 1102/104 fires, it strongly suggests an attacker covering tracks after completing an action, and should be escalated on sight.

> ⚠️ **Caveat:** `$SI` vs `$FN` MFT timestamp comparison isn't something MDE/Sentinel logs natively — it requires offline forensic tooling (e.g. MFTECmd) during IR. The KQL below focuses on the natively-logged, high-fidelity log-clearing signal instead.

## Diagram

```
$STANDARD_INFORMATION (easy to edit)   vs   $FILE_NAME (harder to reach)
      Modified: 2019-03-14                    Modified: 2026-07-08
                    │                                   │
                    └──────────── mismatch ─────────────┘
                              = timestomping tell (offline MFT analysis only)

Event ID 1102 → "The audit log was cleared."          ← escalate immediately
Event ID 104  → "The System/Application log was cleared."
```

## KQL Example

**Variant A — Security log cleared (Event ID 1102):**

```kql
SecurityEvent
| where EventID == 1102
| project TimeGenerated, Computer, SubjectUserName, Activity
| sort by TimeGenerated desc
```

**Variant B — System log cleared (Event ID 104):**

```kql
Event
| where Source == "Microsoft-Windows-Eventlog"
| where EventID == 104
| project TimeGenerated, Computer, UserName, EventID
| sort by TimeGenerated desc
```
