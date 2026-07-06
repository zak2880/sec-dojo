# DNS Tunnelling

- [ ] Read
- [ ] Reviewed KQL example
- [ ] Could explain this to someone else

## Why this matters for detection

DNS is almost never blocked at the perimeter, making it a reliable exfiltration and C2 channel that bypasses most firewall rules.

## Core concept

- Data is encoded (commonly Base32/Base64) and embedded in DNS **query hostnames**: `aGVsbG8gd29ybGQ.attacker.com`. The authoritative server decodes it and replies via TXT/CNAME records.
- Tools: **Iodine** (tunnels IP over DNS), **DNScat2** (interactive C2 shell over DNS), **custom malware** using TXT record responses.
- Key indicators: unusually **long subdomains** (> 50 chars), high **query volume** to a single domain, high **entropy** in subdomain labels, TXT record queries from workstations.

## Diagram

```
Victim → [data encoded in subdomain] → Corp DNS → Attacker's Auth NS
                                                   ← C2 command in TXT record
```

## KQL Example

**Variant A — long subdomain queries:**

Detect long subdomain queries indicative of DNS tunnelling:

```kql
DnsEvents
| extend SubdomainLength = strlen(extract("^([^.]+)\.", 1, Name))
| where SubdomainLength > 50
| summarize count(), dcount(Name) by ClientIP, bin(TimeGenerated, 1h)
| where count_ > 20
```

**Variant B — abnormal TXT-record query volume:**

Not every tunnelling tool relies on long subdomains — some lean on frequent TXT-record lookups to carry command data instead. Flag hosts with abnormally high TXT query volume:

```kql
DnsEvents
| where QueryType == "TXT"
| summarize TxtQueries = count(), DistinctDomains = dcount(Name)
  by ClientIP, bin(TimeGenerated, 1h)
| where TxtQueries > 100
| sort by TxtQueries desc
```
