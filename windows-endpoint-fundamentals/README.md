# sec-dojo — Windows/Endpoint Fundamentals

KQL detection patterns taught through Windows endpoint fundamentals — built for SOC analysts moving into detection engineering. SC-200 / BTL1 level and above.  
Each lesson is under 200 words + a deployable KQL example. Built for ADHD-friendly, focused study sessions.

> **Related:** Detections introduced in sec-dojo are expanded operationally in [soc-runbook](https://github.com/zak2880/soc-runbook) — runbook procedures, triage steps, and production-ready detection rules live there.

---

## Overall Progress

- [ ] Module 01 — Process Fundamentals (3/3 lessons)
- [ ] Module 02 — Sysmon & Event Logs (3/3 lessons)
- [ ] Module 03 — Persistence Mechanisms (3/3 lessons)
- [ ] Module 04 — Credential Access (3/3 lessons)
- [ ] Module 05 — Defense Evasion (3/3 lessons)

---

## Module 01 — Process Fundamentals

| # | Lesson | Read | KQL | Can Explain |
|---|--------|------|-----|-------------|
| 1 | [Process Basics and Trees](01-process-fundamentals/01-process-basics-and-trees.md) | [ ] | [ ] | [ ] |
| 2 | [Process Injection Basics](01-process-fundamentals/02-process-injection-basics.md) | [ ] | [ ] | [ ] |
| 3 | [Living-off-the-Land Binaries](01-process-fundamentals/03-living-off-the-land-binaries.md) | [ ] | [ ] | [ ] |

## Module 02 — Sysmon & Event Logs

| # | Lesson | Read | KQL | Can Explain |
|---|--------|------|-----|-------------|
| 1 | [Sysmon Event IDs Overview](02-sysmon-and-event-logs/01-sysmon-event-ids-overview.md) | [ ] | [ ] | [ ] |
| 2 | [Windows Security Event Essentials](02-sysmon-and-event-logs/02-windows-security-event-essentials.md) | [ ] | [ ] | [ ] |
| 3 | [PowerShell Logging](02-sysmon-and-event-logs/03-powershell-logging.md) | [ ] | [ ] | [ ] |

## Module 03 — Persistence Mechanisms

| # | Lesson | Read | KQL | Can Explain |
|---|--------|------|-----|-------------|
| 1 | [Registry Run Keys and Startup](03-persistence-mechanisms/01-registry-run-keys-and-startup.md) | [ ] | [ ] | [ ] |
| 2 | [Scheduled Tasks and Services](03-persistence-mechanisms/02-scheduled-tasks-and-services.md) | [ ] | [ ] | [ ] |
| 3 | [WMI Persistence](03-persistence-mechanisms/03-wmi-persistence.md) | [ ] | [ ] | [ ] |

## Module 04 — Credential Access

| # | Lesson | Read | KQL | Can Explain |
|---|--------|------|-----|-------------|
| 1 | [LSASS and Credential Dumping](04-credential-access/01-lsass-and-credential-dumping.md) | [ ] | [ ] | [ ] |
| 2 | [Pass-the-Hash Basics](04-credential-access/02-pass-the-hash-basics.md) | [ ] | [ ] | [ ] |
| 3 | [Browser and Clipboard Credential Theft](04-credential-access/03-browser-and-clipboard-credential-theft.md) | [ ] | [ ] | [ ] |

## Module 05 — Defense Evasion

| # | Lesson | Read | KQL | Can Explain |
|---|--------|------|-----|-------------|
| 1 | [AMSI and ETW Bypass Concepts](05-defense-evasion/01-amsi-and-etw-bypass-concepts.md) | [ ] | [ ] | [ ] |
| 2 | [Masquerading and Unsigned Binaries](05-defense-evasion/02-masquerading-and-unsigned-binaries.md) | [ ] | [ ] | [ ] |
| 3 | [Timestomping and Log Clearing](05-defense-evasion/03-timestomping-and-log-clearing.md) | [ ] | [ ] | [ ] |

---

## Quick-reference resources

| Resource | Description |
|---|---|
| [kql-patterns-library.md](kql-patterns-library.md) | Every KQL query in this module, grouped by detection technique (process anomalies, logon & account activity, PowerShell & scripting abuse, persistence, credential access, defense evasion) |
| [glossary.md](glossary.md) | Alphabetical one-line definitions for terms introduced in this module (doesn't repeat terms already defined in the networking module's glossary) |
| [cheatsheets/sysmon-event-id-reference.md](cheatsheets/sysmon-event-id-reference.md) | Sysmon Event ID → what it captures → why it matters for detection |
| [cheatsheets/common-lolbins.md](cheatsheets/common-lolbins.md) | LOLBin → legitimate use → common abuse → MITRE ATT&CK ID |
| [soc-runbook-crossref.md](soc-runbook-crossref.md) | Lesson → corresponding soc-runbook detection/runbook |

## Labs

Hands-on exercises using a Windows lab VM (Sysmon, Event Viewer, native auditing).  
**[→ Open labs/README.md](labs/README.md)**

---

## How to use this repo

1. Open a lesson file.
2. Read the **Core concept** section (2–3 min).
3. Study the **KQL example** — understand what each line does.
4. Tick the checkboxes when you've genuinely done each step.
5. Come back to any lesson you can't explain to someone else.

> **Tip:** GitHub renders the `- [ ]` checkboxes as interactive ticks when you view the file on github.com.

---

## License

[MIT](../LICENSE) — Zak Heeley, 2026
