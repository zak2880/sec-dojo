# ARP Basics

- [ ] Read
- [ ] Reviewed KQL example
- [ ] Could explain this to someone else

## Why this matters for detection

ARP is completely unauthenticated — understanding how it works is the foundation for recognising ARP spoofing, which enables MITM attacks on the same network segment.

## Core concept

- **ARP (Address Resolution Protocol)** maps IP addresses to MAC addresses within a local subnet. When Host A wants to talk to 192.168.1.10, it broadcasts "Who has 192.168.1.10?" and waits for the reply.
- ARP replies are **trustless**: any host can reply to any ARP request (or send an unsolicited "gratuitous ARP") and the OS will update its ARP cache with no verification.
- The ARP cache (`arp -a`) on each host stores IP→MAC mappings. Entries expire after ~20 minutes unless refreshed. Attackers exploit this with unsolicited replies.

## Diagram

```
Broadcast: "Who has 192.168.1.10? Tell 192.168.1.5"
    ↓ (all hosts on segment hear this)
192.168.1.10 replies: "192.168.1.10 is at AA:BB:CC:DD:EE:FF"
192.168.1.5 caches: 192.168.1.10 → AA:BB:CC:DD:EE:FF
```

## KQL Example

Detect ARP cache anomalies — same IP mapping to multiple MACs:

```kql
CommonSecurityLog
| where Activity == "ARP"
| summarize MACs = make_set(DestinationMACAddress) by DestinationIP
| where array_length(MACs) > 1
| project DestinationIP, MACs
```
