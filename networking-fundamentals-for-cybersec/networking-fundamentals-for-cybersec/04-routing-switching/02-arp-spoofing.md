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

> ⚠️ **Note:** Gratuitous ARP is L2 traffic invisible to `DeviceNetworkEvents`. Option A requires a Zeek sensor on the segment; Option B requires a managed switch with Dynamic ARP Inspection (DAI) forwarding syslog to Sentinel.

**Option A — Zeek `arp.log` ingested as `Zeek_ARP_CL`:**

Flag a host claiming ownership of multiple IPs (spoofer signature):

```kql
Zeek_ARP_CL
| where TimeGenerated > ago(5m)
| where isGratuitous == true or mac_src != mac_orig   // unsolicited or mismatched reply
| summarize SpoofedIPs = make_set(dst_ip), count()
  by mac_src, src_ip
| where array_length(SpoofedIPs) > 1 or count_ > 30
| sort by count_ desc
```

**Option B — Switch DAI syslog via `CommonSecurityLog`:**

Detect DAI violations logged by a Cisco switch with ARP Inspection enabled:

```kql
CommonSecurityLog
| where TimeGenerated > ago(1h)
| where DeviceVendor == "Cisco" and Activity == "SW_DAI"
| where Message has "ARP_Inspect" and Message has "DHCP_SNOOPING_DENY"
| project TimeGenerated, DeviceName, SourceIP, SourceMACAddress, Message
| sort by TimeGenerated desc
```
