# DNS Resolution Basics

- [ ] Read
- [ ] Reviewed KQL example
- [ ] Could explain this to someone else

## Why this matters for detection

Nearly every attacker action starts with a DNS query — C2 check-ins, phishing redirects, data exfiltration — making DNS logs one of the highest-value sources in your SIEM.

## Core concept

- **Resolution chain**: stub resolver → recursive resolver → root nameserver → TLD nameserver → authoritative nameserver → answer. Your endpoint's DNS queries hit the recursive resolver first (usually your ISP or internal DNS server).
- **Record types to know**: A (IPv4), AAAA (IPv6), CNAME (alias), MX (mail), TXT (used for SPF/DKIM and also abused for tunnelling), NS (nameserver).
- DNS responses are cached using **TTL**. Very short TTLs (< 60 s) are a DGA / fast-flux red flag because attackers rotate IPs rapidly to avoid blocklists.

## Diagram

```
Endpoint → Recursive Resolver → Root NS (.)
                              → TLD NS (.com)
                              → Auth NS (example.com)
                              ← A record: 93.184.216.34
```

## KQL Example

Find endpoints querying domains with suspiciously short TTLs:

```kql
DnsEvents
| where QueryType == "A"
| where TTL < 60 and TTL > 0
| summarize count() by Name, ClientIP
| sort by count_ desc
```
