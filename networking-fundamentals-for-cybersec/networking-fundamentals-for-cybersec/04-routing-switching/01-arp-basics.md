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

> ⚠️ **Note:** ARP is L2 traffic. `CommonSecurityLog` and `DeviceNetworkEvents` do not capture ARP frames. This requires a network sensor (e.g. Zeek, Suricata, Arkime) with a tap or SPAN port, ingested into a custom Sentinel table.

**Option A — Zeek `arp.log` ingested as `Zeek_ARP_CL`:**

Detect IP-to-MAC instability — the hallmark of ARP spoofing:

```kql
Zeek_ARP_CL
| where TimeGenerated > ago(1h)
| summarize MACs = make_set(dst_mac), Changes = count()
  by dst_ip
| where array_length(MACs) > 1   // same IP advertising multiple MACs
| project dst_ip, MACs, Changes
| sort by Changes desc
```

**Option B — Zeek `conn.log` ingested as `Zeek_Conn_CL` (indirect pivot):**

Flag local hosts generating unusually high broadcast-range connection counts, which may indicate ARP-based scanning:

```kql
Zeek_Conn_CL
| where TimeGenerated > ago(10m)
| where id_resp_h endswith ".255" or id_resp_h == "255.255.255.255"
| summarize BroadcastCount = count() by id_orig_h, bin(TimeGenerated, 1m)
| where BroadcastCount > 50
| sort by BroadcastCount desc
```
