# sec-dojo

Bite-sized theory lessons for cybersecurity fundamentals — built for fast, focused learning. Each lesson covers one concept, ties it to real-world attacker behavior, and links it to a practical detection use case (KQL/Sentinel). Starting with networking, expanding across other security domains over time.

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
└── (more modules coming soon)
```

---

## Modules

| Module | Status | Description |
|---|---|---|
| [01 — Networking Fundamentals for Cybersec](networking-fundamentals-for-cybersec/README.md) | Active | OSI/TCP-IP, DNS, HTTP/TLS, routing & switching, C2 & beaconing — SC-200 / BTL1 level, each lesson paired with a KQL detection |
| 02 — TBD | Coming soon | Next security domain, expanding the same bite-sized lesson + detection format |

---

## License

[MIT](LICENSE) — Zak Heeley, 2026
