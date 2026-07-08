# sec-dojo

KQL detection patterns taught through networking fundamentals — built for SOC analysts moving into detection engineering. Each lesson covers one concept, ties it to real-world attacker behavior, and pairs it with a deployable KQL/Sentinel detection. Starting with networking, expanding across other security domains over time.

---

## Structure

```
sec-dojo/
├── networking-fundamentals-for-cybersec/   ← Module 1
│   ├── 01-osi-tcp-ip/
│   ├── 02-dns/
│   ├── 03-http-tls/
│   ├── 04-routing-switching/
│   ├── 05-c2-and-beaconing/
│   ├── cheatsheets/          ← quick-reference tables
│   ├── labs/                 ← hands-on Zeek/tcpdump exercises
│   ├── glossary.md           ← one-line term definitions
│   └── soc-runbook-crossref.md
├── windows-endpoint-fundamentals/           ← Module 2
│   ├── 01-process-fundamentals/
│   ├── 02-sysmon-and-event-logs/
│   ├── 03-persistence-mechanisms/
│   ├── 04-credential-access/
│   ├── 05-defense-evasion/
│   ├── cheatsheets/          ← quick-reference tables
│   ├── labs/                 ← hands-on Sysmon/Event Viewer exercises
│   ├── glossary.md           ← one-line term definitions
│   └── soc-runbook-crossref.md
└── (more modules coming soon)
```

---

## Modules

| Module | Status | Description |
|---|---|---|
| [01 — Networking Fundamentals for Cybersec](networking-fundamentals-for-cybersec/README.md) | Active | KQL detection patterns for OSI/TCP-IP, DNS, HTTP/TLS, routing & switching, C2 & beaconing — SC-200 / BTL1 level |
| [02 — Windows/Endpoint Fundamentals](windows-endpoint-fundamentals/README.md) | Active | KQL detection patterns for process fundamentals, Sysmon & event logs, persistence, credential access, and defense evasion — SC-200 / BTL1 level |

---

## License

[MIT](LICENSE) — Zak Heeley, 2026
