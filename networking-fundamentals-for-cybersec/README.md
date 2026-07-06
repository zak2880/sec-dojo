# sec-dojo

A growing library of bite-sized cybersecurity lessons for SOC analysts — SC-200 / BTL1 level and above.

Each topic module contains short lessons (under 200 words each), ASCII diagrams, and real KQL examples written for Microsoft Sentinel / MDE, plus callouts where a network sensor (Zeek, Suricata) is required for full fidelity.

> **Related:** Detections introduced in sec-dojo are expanded operationally in [soc-runbook](https://github.com/zak2880/soc-runbook) — runbook procedures, triage steps, and production-ready detection rules live there.

---

## Structure

```
sec-dojo/
├── networking-fundamentals-for-cybersec/   ← Module 1 (active)
├── cheatsheets/                            ← Quick-reference tables
├── labs/                                   ← Hands-on exercises (Zeek, tcpdump, Suricata)
├── glossary.md                             ← One-line term definitions
└── soc-runbook-crossref.md                 ← Lesson → soc-runbook cross-reference
```

---

## Modules

### Module 1 — Networking Fundamentals

> 15 lessons covering OSI/TCP-IP, DNS, HTTP/TLS, ARP/switching, and C2 beaconing detection.

**[→ Open the Networking Fundamentals module](networking-fundamentals-for-cybersec/README.md)**

| Topic area | Lessons |
|---|---|
| OSI & TCP/IP | OSI model, TCP handshake, UDP vs TCP |
| DNS | Resolution basics, DNS tunnelling, DGA detection |
| HTTP & TLS | HTTP anatomy, TLS handshake, JA3 fingerprinting |
| Routing & Switching | ARP basics, ARP spoofing, VLAN hopping |
| C2 & Beaconing | What is beaconing, jitter/sleep, KQL beacon hunter |

---

### Module 2 — Endpoint Telemetry *(coming soon)*

Planned lessons: process injection, LSASS access, LOLBins, WMI abuse, Sysmon event mapping.

### Module 3 — Identity & Authentication *(coming soon)*

Planned lessons: Kerberoasting, Pass-the-Hash, Azure AD sign-in anomalies, MFA fatigue.

### Module 4 — Cloud & SaaS *(coming soon)*

Planned lessons: Azure resource creation, storage access anomalies, OAuth consent phishing, CloudTrail basics.

### Module 5 — Threat Intel & Hunting *(coming soon)*

Planned lessons: IOC lifecycle, MITRE ATT&CK navigation, hypothesis-driven hunting, pivot techniques.

---

## Quick-reference resources

| Resource | Description |
|---|---|
| [glossary.md](glossary.md) | Alphabetical one-line definitions for all terms used across modules |
| [cheatsheets/common-ports.md](cheatsheets/common-ports.md) | Port → protocol → detection relevance |
| [cheatsheets/protocol-abuse-matrix.md](cheatsheets/protocol-abuse-matrix.md) | Legitimate protocol → common abuse → MITRE ATT&CK ID |
| [soc-runbook-crossref.md](soc-runbook-crossref.md) | Lesson → corresponding soc-runbook detection/runbook |

## Labs

Hands-on exercises using homelab tools (Zeek, Suricata, tcpdump on archerserver).  
**[→ Open labs/README.md](labs/README.md)**

---

## License

[MIT](LICENSE) — Zak Heeley, 2026
