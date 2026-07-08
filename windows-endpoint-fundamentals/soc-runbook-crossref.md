# SOC Runbook Cross-Reference

Maps sec-dojo lessons to their corresponding detection rules, triage procedures, and KQL in [soc-runbook](https://github.com/zak2880/soc-runbook).

> **How to use:** When you complete a sec-dojo lesson, look it up here to find the operational runbook entry where that concept is implemented as a production detection. The sec-dojo lesson explains the *why*; the soc-runbook entry shows the *what to do when it fires*.

---

## Windows — Process Fundamentals

| Sec-Dojo Lesson | Concept | soc-runbook Scenario / KQL File |
|---|---|---|
| [Process Basics and Trees](01-process-fundamentals/01-process-basics-and-trees.md) | Parent-child process anomaly triage | TBD |
| [Process Injection Basics](01-process-fundamentals/02-process-injection-basics.md) | ASR-based injection / unsigned image-load detection | TBD |
| [Living-off-the-Land Binaries](01-process-fundamentals/03-living-off-the-land-binaries.md) | LOLBin command-line and egress correlation | TBD |

## Windows — Sysmon & Event Logs

| Sec-Dojo Lesson | Concept | soc-runbook Scenario / KQL File |
|---|---|---|
| [Sysmon Event IDs Overview](02-sysmon-and-event-logs/01-sysmon-event-ids-overview.md) | Core Sysmon EID triage reference | TBD |
| [Windows Security Event Essentials](02-sysmon-and-event-logs/02-windows-security-event-essentials.md) | 4625 spray / 4672 privilege-assignment triage | TBD |
| [PowerShell Logging](02-sysmon-and-event-logs/03-powershell-logging.md) | Encoded command / script block obfuscation triage | TBD |

## Windows — Persistence Mechanisms

| Sec-Dojo Lesson | Concept | soc-runbook Scenario / KQL File |
|---|---|---|
| [Registry Run Keys and Startup](03-persistence-mechanisms/01-registry-run-keys-and-startup.md) | Run/RunOnce and Startup-folder persistence triage | TBD |
| [Scheduled Tasks and Services](03-persistence-mechanisms/02-scheduled-tasks-and-services.md) | Suspicious scheduled task / service-install triage | TBD |
| [WMI Persistence](03-persistence-mechanisms/03-wmi-persistence.md) | WMI event subscription persistence triage | TBD |

## Windows — Credential Access

| Sec-Dojo Lesson | Concept | soc-runbook Scenario / KQL File |
|---|---|---|
| [LSASS and Credential Dumping](04-credential-access/01-lsass-and-credential-dumping.md) | LSASS access / comsvcs.dll dump triage | TBD |
| [Pass-the-Hash Basics](04-credential-access/02-pass-the-hash-basics.md) | Multi-host logon / NTLM-volume triage | TBD |
| [Browser and Clipboard Credential Theft](04-credential-access/03-browser-and-clipboard-credential-theft.md) | Infostealer credential-store access triage | TBD |

## Windows — Defense Evasion

| Sec-Dojo Lesson | Concept | soc-runbook Scenario / KQL File |
|---|---|---|
| [AMSI and ETW Bypass Concepts](05-defense-evasion/01-amsi-and-etw-bypass-concepts.md) | AMSI/ETW bypass attempt triage | TBD |
| [Masquerading and Unsigned Binaries](05-defense-evasion/02-masquerading-and-unsigned-binaries.md) | Path/signer mismatch triage | TBD |
| [Timestomping and Log Clearing](05-defense-evasion/03-timestomping-and-log-clearing.md) | 1102/104 log-clearing escalation playbook | TBD |
