# ARP Spoofing

- [ ] Read
- [ ] Reviewed KQL example
- [ ] Could explain this to someone else

## Why this matters for detection

ARP spoofing is the entry point for LAN-based MITM attacks — credentials, session tokens, and cleartext data all flow through the attacker's machine without the victim noticing.

## Core concept

- The attacker sends **gratuitous ARP replies** (unsolicited) to both the victim and the gateway: "192.168.1.1 is at [attacker MAC]" and "192.168.1.5 is at [attacker MAC]". Both hosts update their ARP caches.
- Traffic flows: Victim → Attacker → Gateway → Internet. The attacker is now a silent relay — they can read, modify, or drop packets.
- Tools: **arpspoof** (dsniff suite), **Ettercap**, **Bettercap**. Defences: **Dynamic ARP Inspection (DAI)** on managed switches, static ARP entries for critical hosts.

## Diagram

```
Normal:  Victim ──────────────────→ Gateway → Internet
Spoofed: Victim → Attacker (MITM) → Gateway → Internet
              ↑ ARP: "GW = attacker MAC"
```

## KQL Example

Detect a host sending gratuitous ARPs at high volume (potential spoofer):

```kql
CommonSecurityLog
| where Activity == "ARP" and isnotempty(SourceMACAddress)
| where Message has "gratuitous" or Message has "announcement"
| summarize count() by SourceMACAddress, SourceIP, bin(TimeGenerated, 1m)
| where count_ > 30
```
