# Rogue DHCP & DHCP Starvation

- [ ] Read
- [ ] Reviewed KQL example
- [ ] Could explain this to someone else

## Why this matters for detection

A rogue DHCP server hands out attacker-controlled gateway/DNS settings to every new client on the segment — the same MITM outcome as [ARP Spoofing](02-arp-spoofing.md), but achieved at lease time instead of by poisoning caches one host at a time.

## Core concept

- **Normal DHCP (DORA)**: client broadcasts **Discover** → server sends **Offer** → client broadcasts **Request** (accepting the offer) → server confirms with **Acknowledge**, which includes lease details like default gateway and DNS server.
- **DHCP starvation**: an attacker floods the segment with Discover requests using spoofed source MACs, each claiming a lease, until the legitimate server's address pool is exhausted.
- **Rogue DHCP server**: once the real pool is starved (or simply by racing the legitimate server to answer first), the attacker's own DHCP server starts responding to new clients — handing out its own IP as the gateway and/or DNS server, putting it in the traffic path for everything those clients do.
- Defence: **DHCP snooping** on managed switches builds a trusted/untrusted port table and drops DHCP server messages (Offer/Ack) arriving on untrusted access ports. The same snooping table underpins **Dynamic ARP Inspection**, already covered in the ARP spoofing lesson.

## Diagram

```
Normal DORA:    Client → Discover (broadcast) → Real DHCP Server
                Client ← Offer     ←─────────────┘
                Client → Request (broadcast)     →┐
                Client ← Ack       ←───────────────┘ (gateway=10.0.0.1, dns=10.0.0.2)

Starved+Rogue:  Attacker floods Discovers (spoofed MACs) → real pool exhausted
                New client → Discover → Rogue DHCP answers first
                Client ← Ack (gateway=ATTACKER, dns=ATTACKER)  ← MITM
```

## KQL Example

> ⚠️ **Note:** DHCP is L2/L3 broadcast traffic outside `DeviceNetworkEvents`. Option A requires switch syslog from a managed switch with DHCP snooping enabled; Option B requires a Zeek sensor with DHCP visibility.

**Option A — DHCP snooping violations via switch syslog (`CommonSecurityLog`, same pattern as the VLAN hopping and ARP spoofing lessons):**

```kql
CommonSecurityLog
| where TimeGenerated > ago(1h)
| where DeviceVendor == "Cisco"
| where Message has "DHCP_SNOOPING_UNTRUSTED_PORT"    // SW_DHCP_SNOOPING-5 — DHCP server reply seen on an untrusted access port
       or Message has "DHCP_SNOOPING_MATCH_MAC_FAIL"  // SW_DHCP_SNOOPING-4 — client MAC mismatch, common in starvation floods
| project TimeGenerated, DeviceName, SourceIP, SourceMACAddress, Message
| sort by TimeGenerated desc
```

**Option B — Zeek `dhcp.log` ingested as `Zeek_DHCP_CL` (abnormal request volume from one MAC):**

A legitimate host sends one Discover per lease request, not hundreds per minute:

```kql
Zeek_DHCP_CL
| where TimeGenerated > ago(5m)
| where msg_types has "DISCOVER"
| summarize DiscoverCount = count() by mac, bin(TimeGenerated, 1m)
| where DiscoverCount > 100
| sort by DiscoverCount desc
```
