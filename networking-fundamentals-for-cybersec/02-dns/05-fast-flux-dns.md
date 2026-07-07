# Fast-Flux DNS

- [ ] Read
- [ ] Reviewed KQL example
- [ ] Could explain this to someone else

## Why this matters for detection

Fast-flux gives C2 infrastructure the same takedown resistance as a DGA, but by rotating IPs behind one stable domain instead of burning through domain names — a very different detection surface from what [DGA Detection](03-dga-detection.md) covers.

## Core concept

- **Fast-flux vs DGA**: a DGA generates many *domain names* pointing at one (or a few) IPs. Fast-flux keeps a *single domain* but rotates it across a large, constantly-changing pool of bot IPs with very short TTLs.
- **Single-flux**: only the domain's **A records** rotate rapidly among compromised host IPs acting as reverse proxies in front of the real C2 backend.
- **Double-flux**: the domain's **NS records** (the authoritative nameservers themselves) also rotate across the same fast-changing bot infrastructure — so even seizing or blocking the A-record targets doesn't stop resolution, because the nameservers answering for the domain keep moving too.
- Detection angle: a legitimate domain resolves to a small, stable set of IPs. A domain resolving to dozens of distinct IPs within minutes — especially spread across unrelated ASNs/geographies — is the fast-flux signature.

## Diagram

```
attacker-c2.tld  (TTL = 60s)
  t=0    → 45.33.12.9    (bot #1, BR)
  t=60   → 91.121.9.44   (bot #2, FR)
  t=120  → 203.0.113.7   (bot #3, VN)
  ...dozens of distinct IPs answering the SAME name within minutes

Double-flux: NS records for attacker-c2.tld ALSO rotate across bot IPs
```

## KQL Example

**Variant A — single-flux: domain resolving to unusually many distinct IPs:**

```kql
DnsEvents
| where TimeGenerated > ago(1h)
| where QueryType == "A"
| summarize DistinctIPs = dcount(IPAddress), Resolutions = count()
  by Name, bin(TimeGenerated, 10m)
| where DistinctIPs > 15   // legitimate domains rarely rotate this many IPs this fast
| sort by DistinctIPs desc
```

**Variant B — double-flux: the nameservers themselves are rotating:**

Variant A alone misses double-flux, where the A records could look comparatively stable while the NS delegation churns instead. Apply the same distinct-count hypothesis to NS lookups:

```kql
DnsEvents
| where TimeGenerated > ago(1h)
| where QueryType == "NS"
| summarize DistinctNS = dcount(IPAddress), Resolutions = count()
  by Name, bin(TimeGenerated, 30m)
| where DistinctNS > 5   // even the authoritative nameservers are rotating
| sort by DistinctNS desc
```
