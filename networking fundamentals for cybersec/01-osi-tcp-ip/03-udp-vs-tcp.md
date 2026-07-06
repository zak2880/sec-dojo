# UDP vs TCP

- [ ] Read
- [ ] Reviewed KQL example
- [ ] Could explain this to someone else

## Why this matters for detection

Attackers choose UDP for tunnelling and exfiltration specifically because many security tools focus on TCP — knowing the difference helps you tune rules for both.

## Core concept

- **TCP** is connection-oriented: handshake, ordered delivery, retransmission, teardown. High overhead, but reliable. Most application traffic uses TCP.
- **UDP** is connectionless: fire-and-forget, no handshake, no guaranteed delivery. Used by DNS (port 53), DHCP, NTP, QUIC, VoIP.
- Attackers exploit UDP's low visibility: DNS tunnelling uses UDP/53, some C2 frameworks use UDP to blend with DNS/NTP traffic. Large UDP payloads or unusual destination ports are red flags.

## Diagram

```
TCP                         UDP
────────────────────        ────────────────────
SYN → SYN-ACK → ACK        [no handshake]
Data (ordered)              Data (unordered, lossy OK)
FIN → FIN-ACK              [no teardown]
Stateful                    Stateless
```

## KQL Example

Flag large UDP packets on DNS port — potential DNS tunnelling:

```kql
NetworkCommunicationEvents
| where Protocol == "Udp" and RemotePort == 53
| where SentBytes > 512
| project Timestamp, DeviceName, RemoteIP, SentBytes, InitiatingProcessFileName
| sort by SentBytes desc
```
