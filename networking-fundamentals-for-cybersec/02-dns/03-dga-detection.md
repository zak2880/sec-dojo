# Domain Generation Algorithm (DGA) Detection

- [ ] Read
- [ ] Reviewed KQL example
- [ ] Could explain this to someone else

## Why this matters for detection

DGAs let malware generate thousands of potential C2 domains algorithmically so that blocklisting a few domains has no effect — detecting the pattern beats chasing individual domains.

## Core concept

- Malware seeds a PRNG with a value (often the current date) and generates hundreds/thousands of domain names. Only the attacker registers one — the malware just tries all of them until it gets an answer.
- DGA domains have **high lexical entropy**: random-looking strings like `qztrplmxcv.com` vs readable legitimate domains. Tools like **FLOSS** or **BI.ZONE** DGA feeds classify these.
- Detection approach: flag **NXDOMAIN storms** (many failed lookups from one host) and domains with high consonant ratios or vowel-to-consonant imbalance.

## Diagram

```
Seed (date) → PRNG → Domain list:
  xkqpvmr[.]com  → NXDOMAIN
  btzwqpl[.]com  → NXDOMAIN
  crvmqxp[.]com  → RESOLVED ← attacker's active C2
```

## KQL Example

Detect NXDOMAIN storms — a host failing DNS for many unique domains:

```kql
DnsEvents
| where ResultCode == "NXDOMAIN"
| summarize FailedDomains = dcount(Name), TotalQueries = count()
  by ClientIP, bin(TimeGenerated, 10m)
| where FailedDomains > 50
| sort by FailedDomains desc
```
