# VLAN Hopping

- [ ] Read
- [ ] Reviewed KQL example
- [ ] Could explain this to someone else

## Why this matters for detection

VLANs are a common network segmentation control — VLAN hopping defeats that segmentation, letting an attacker reach sensitive subnets (e.g. server VLAN, OT networks) from a compromised workstation.

## Core concept

- **Switch Spoofing**: the attacker configures their NIC to negotiate a trunk link using DTP (Dynamic Trunking Protocol). If the switch port is in dynamic auto/desirable mode, it forms a trunk and passes all VLAN traffic to the attacker.
- **Double Tagging**: the attacker sends a frame with two 802.1Q VLAN tags. The first switch strips the outer tag (native VLAN) and forwards — the inner tag carries the frame to the target VLAN. Only works one-way.
- Mitigation: disable DTP (`switchport nonegotiate`), set unused ports to access mode, change the native VLAN away from VLAN 1.

## Diagram

```
Double-tag frame:  [Outer: VLAN 1][Inner: VLAN 10][Payload]
Switch 1 strips outer tag → forwards on trunk
Switch 2 sees inner tag → delivers to VLAN 10 ✓ (attacker wins)
```

## KQL Example

> ⚠️ **Note:** This query requires Cisco switch syslog forwarded to Sentinel via the `CommonSecurityLog` connector. The messages below are real Cisco IOS/IOS-XE log strings.

Detect native VLAN mismatches and unexpected trunk negotiations from switch syslog:

```kql
CommonSecurityLog
| where TimeGenerated > ago(1h)
| where DeviceVendor == "Cisco"
| where Message has "Native VLAN mismatch"   // CDP-4-NATIVE_VLAN_MISMATCH — real Cisco log
       or Message has "TRUNKPORTON"           // DTP-5-TRUNKPORTON — unexpected trunk formed
       or Message has "DYNAMICTRUNK"          // DTP negotiated a trunk on an access port
| project TimeGenerated, DeviceName, SourceIP, Message
| sort by TimeGenerated desc
```
