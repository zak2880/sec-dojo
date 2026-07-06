# OSI Model

- [ ] Read
- [ ] Reviewed KQL example
- [ ] Could explain this to someone else

## Why this matters for detection

Knowing which OSI layer an attack targets tells you what data sources to query and what artefacts to look for in alerts.

## Core concept

- **7 layers** (Physical → Data Link → Network → Transport → Session → Presentation → Application). For detection, focus on L3–L7.
- Network-layer attacks (L3) = IP spoofing, ICMP floods. Transport-layer (L4) = SYN floods, port scans. Application-layer (L7) = HTTP exploits, DNS tunnelling.
- Each layer adds a **header** (encapsulation). Attackers abuse headers to hide data or bypass controls — knowing the model lets you spot anomalies in the right field.

## Diagram

```
L7 Application  ← HTTP, DNS, SMTP (most alerts live here)
L6 Presentation ← TLS encryption/decryption
L5 Session      ← Session tracking
L4 Transport    ← TCP/UDP ports, flow state
L3 Network      ← IP addresses, routing
L2 Data Link    ← MAC addresses, ARP, VLANs
L1 Physical     ← Cables, signals
```

## KQL Example

Identify traffic hitting unusual destination ports (L4 anomaly):

```kql
DeviceNetworkEvents
| where RemotePort !in (80, 443, 53, 22, 25, 445)
| summarize count() by RemotePort, InitiatingProcessFileName
| sort by count_ desc
```
