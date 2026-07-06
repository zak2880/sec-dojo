# SOC Runbook Cross-Reference

Maps sec-dojo lessons to their corresponding detection rules, triage procedures, and KQL in [soc-runbook](https://github.com/zak2880/soc-runbook).

> **How to use:** When you complete a sec-dojo lesson, look it up here to find the operational runbook entry where that concept is implemented as a production detection. The sec-dojo lesson explains the *why*; the soc-runbook entry shows the *what to do when it fires*.

---

## Networking — OSI & TCP/IP

| Sec-Dojo Lesson | Concept | soc-runbook Scenario / KQL File |
|---|---|---|
| [OSI Model](networking-fundamentals-for-cybersec/01-osi-tcp-ip/01-osi-model.md) | Layer-based triage framework | TBD |
| [TCP Handshake](networking-fundamentals-for-cybersec/01-osi-tcp-ip/02-tcp-handshake.md) | SYN flood / port scan detection | TBD |
| [UDP vs TCP](networking-fundamentals-for-cybersec/01-osi-tcp-ip/03-udp-vs-tcp.md) | Protocol anomaly alerting | TBD |

## Networking — DNS

| Sec-Dojo Lesson | Concept | soc-runbook Scenario / KQL File |
|---|---|---|
| [DNS Resolution Basics](networking-fundamentals-for-cybersec/02-dns/01-dns-resolution-basics.md) | Short-TTL / fast-flux detection | TBD |
| [DNS Tunnelling](networking-fundamentals-for-cybersec/02-dns/02-dns-tunneling.md) | Long-subdomain exfiltration alert | TBD |
| [DGA Detection](networking-fundamentals-for-cybersec/02-dns/03-dga-detection.md) | NXDOMAIN storm triage playbook | TBD |

## Networking — HTTP & TLS

| Sec-Dojo Lesson | Concept | soc-runbook Scenario / KQL File |
|---|---|---|
| [HTTP Request Anatomy](networking-fundamentals-for-cybersec/03-http-tls/01-http-request-anatomy.md) | Anomalous User-Agent / proxy log triage | TBD |
| [TLS Handshake](networking-fundamentals-for-cybersec/03-http-tls/02-tls-handshake.md) | Self-signed cert alert response | TBD |
| [JA3 Fingerprinting](networking-fundamentals-for-cybersec/03-http-tls/03-ja3-fingerprinting.md) | Known-bad JA3 match triage | TBD |

## Networking — Routing & Switching

| Sec-Dojo Lesson | Concept | soc-runbook Scenario / KQL File |
|---|---|---|
| [ARP Basics](networking-fundamentals-for-cybersec/04-routing-switching/01-arp-basics.md) | ARP anomaly baseline | TBD |
| [ARP Spoofing](networking-fundamentals-for-cybersec/04-routing-switching/02-arp-spoofing.md) | MITM via ARP — detection and isolation | TBD |
| [VLAN Hopping](networking-fundamentals-for-cybersec/04-routing-switching/03-vlan-hopping.md) | Switch misconfig detection | TBD |

## Networking — C2 & Beaconing

| Sec-Dojo Lesson | Concept | soc-runbook Scenario / KQL File |
|---|---|---|
| [What is Beaconing?](networking-fundamentals-for-cybersec/05-c2-and-beaconing/01-what-is-beaconing.md) | C2 beacon identification workflow | TBD |
| [Jitter and Sleep](networking-fundamentals-for-cybersec/05-c2-and-beaconing/02-jitter-and-sleep.md) | Jittered beacon statistical hunting | TBD |
| [Detecting Beacon Patterns (KQL)](networking-fundamentals-for-cybersec/05-c2-and-beaconing/03-detecting-beacon-patterns-kql.md) | Beacon hunter alert — triage and escalation | TBD |
