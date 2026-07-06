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

Detect 802.1Q-tagged traffic sourced from endpoint devices (workstations shouldn't send tagged frames):

```kql
CommonSecurityLog
| where DeviceVendor == "Cisco" or DeviceVendor == "Palo Alto Networks"
| where Message has "vlan-hop" or Message has "double-tag" or Message has "native vlan mismatch"
| project TimeGenerated, DeviceName, SourceIP, SourceMACAddress, Message
```
