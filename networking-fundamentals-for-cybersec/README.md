# sec-dojo — Networking Fundamentals for Cybersec

KQL detection patterns taught through networking fundamentals — built for SOC analysts moving into detection engineering. SC-200 / BTL1 level and above.  
Each lesson is under 200 words + a deployable KQL example. Built for ADHD-friendly, focused study sessions.

> **Related:** Detections introduced in sec-dojo are expanded operationally in [soc-runbook](https://github.com/zak2880/soc-runbook) — runbook procedures, triage steps, and production-ready detection rules live there.

---

## Overall Progress

- [ ] Module 01 — OSI & TCP/IP (4/4 lessons)
- [ ] Module 02 — DNS (5/5 lessons)
- [ ] Module 03 — HTTP & TLS (5/5 lessons)
- [ ] Module 04 — Routing & Switching (4/4 lessons)
- [ ] Module 05 — C2 & Beaconing (5/5 lessons)

---

## Module 01 — OSI & TCP/IP

| # | Lesson | Read | KQL | Can Explain |
|---|--------|------|-----|-------------|
| 1 | [OSI Model](01-osi-tcp-ip/01-osi-model.md) | [ ] | [ ] | [ ] |
| 2 | [TCP Three-Way Handshake](01-osi-tcp-ip/02-tcp-handshake.md) | [ ] | [ ] | [ ] |
| 3 | [UDP vs TCP](01-osi-tcp-ip/03-udp-vs-tcp.md) | [ ] | [ ] | [ ] |
| 4 | [ICMP & ICMP Tunnelling](01-osi-tcp-ip/04-icmp-tunnelling.md) | [ ] | [ ] | [ ] |

## Module 02 — DNS

| # | Lesson | Read | KQL | Can Explain |
|---|--------|------|-----|-------------|
| 1 | [DNS Resolution Basics](02-dns/01-dns-resolution-basics.md) | [ ] | [ ] | [ ] |
| 2 | [DNS Tunnelling](02-dns/02-dns-tunneling.md) | [ ] | [ ] | [ ] |
| 3 | [DGA Detection](02-dns/03-dga-detection.md) | [ ] | [ ] | [ ] |
| 4 | [DoH/DoT as a Detection Blind Spot](02-dns/04-doh-dot-blindspot.md) | [ ] | [ ] | [ ] |
| 5 | [Fast-Flux DNS](02-dns/05-fast-flux-dns.md) | [ ] | [ ] | [ ] |

## Module 03 — HTTP & TLS

| # | Lesson | Read | KQL | Can Explain |
|---|--------|------|-----|-------------|
| 1 | [HTTP Request Anatomy](03-http-tls/01-http-request-anatomy.md) | [ ] | [ ] | [ ] |
| 2 | [TLS Handshake](03-http-tls/02-tls-handshake.md) | [ ] | [ ] | [ ] |
| 3 | [JA3 TLS Fingerprinting](03-http-tls/03-ja3-fingerprinting.md) | [ ] | [ ] | [ ] |
| 4 | [Domain Fronting](03-http-tls/04-domain-fronting.md) | [ ] | [ ] | [ ] |
| 5 | [JARM Server Fingerprinting](03-http-tls/05-jarm-fingerprinting.md) | [ ] | [ ] | [ ] |

## Module 04 — Routing & Switching

| # | Lesson | Read | KQL | Can Explain |
|---|--------|------|-----|-------------|
| 1 | [ARP Basics](04-routing-switching/01-arp-basics.md) | [ ] | [ ] | [ ] |
| 2 | [ARP Spoofing](04-routing-switching/02-arp-spoofing.md) | [ ] | [ ] | [ ] |
| 3 | [VLAN Hopping](04-routing-switching/03-vlan-hopping.md) | [ ] | [ ] | [ ] |
| 4 | [Rogue DHCP & DHCP Starvation](04-routing-switching/04-rogue-dhcp.md) | [ ] | [ ] | [ ] |

## Module 05 — C2 & Beaconing

| # | Lesson | Read | KQL | Can Explain |
|---|--------|------|-----|-------------|
| 1 | [What is Beaconing?](05-c2-and-beaconing/01-what-is-beaconing.md) | [ ] | [ ] | [ ] |
| 2 | [Jitter and Sleep Intervals](05-c2-and-beaconing/02-jitter-and-sleep.md) | [ ] | [ ] | [ ] |
| 3 | [Detecting Beacon Patterns with KQL](05-c2-and-beaconing/03-detecting-beacon-patterns-kql.md) | [ ] | [ ] | [ ] |
| 4 | [C2 over Legitimate Services (SaaS-based C2)](05-c2-and-beaconing/04-c2-legitimate-services.md) | [ ] | [ ] | [ ] |
| 5 | [Malleable C2 Profiles](05-c2-and-beaconing/05-malleable-c2-profiles.md) | [ ] | [ ] | [ ] |

---

## Quick-reference resources

| Resource | Description |
|---|---|
| [kql-patterns-library.md](kql-patterns-library.md) | Every KQL query in this module, grouped by detection technique (beaconing, DNS anomalies/evasion, TLS/cert fingerprinting/C2 evasion, recon/lateral movement, ICMP/protocol abuse) |
| [glossary.md](glossary.md) | Alphabetical one-line definitions for all terms used across modules |
| [cheatsheets/common-ports.md](cheatsheets/common-ports.md) | Port → protocol → detection relevance |
| [cheatsheets/protocol-abuse-matrix.md](cheatsheets/protocol-abuse-matrix.md) | Legitimate protocol → common abuse → MITRE ATT&CK ID |
| [soc-runbook-crossref.md](soc-runbook-crossref.md) | Lesson → corresponding soc-runbook detection/runbook |

## Labs

Hands-on exercises using homelab tools (Zeek, Suricata, tcpdump on your homelab/sensor host).  
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
