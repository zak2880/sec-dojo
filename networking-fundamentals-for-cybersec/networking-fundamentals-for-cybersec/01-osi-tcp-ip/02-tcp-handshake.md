# TCP Three-Way Handshake

- [ ] Read
- [ ] Reviewed KQL example
- [ ] Could explain this to someone else

## Why this matters for detection

Half-open connections and asymmetric SYN/ACK ratios are classic signatures of port scans and SYN flood DoS attacks.

## Core concept

- **SYN → SYN-ACK → ACK**: client sends SYN, server replies SYN-ACK, client completes with ACK. Connection is now established.
- A **SYN with no ACK** reply means the port is closed (RST) or filtered. Port scanners deliberately send SYN packets and read responses without completing the handshake.
- **TCP flags** in packet headers (SYN, ACK, RST, FIN, PSH, URG) tell you the connection state. Unexpected flag combos (e.g. SYN+FIN) are used by stealthy scanners like Nmap's XMAS scan.

## Diagram

```
Client              Server
  |--- SYN --------->|   seq=100
  |<-- SYN-ACK ------|   seq=200, ack=101
  |--- ACK --------->|   ack=201
  |== ESTABLISHED ===|
```

## KQL Example

Detect hosts generating high-volume connection attempts to many distinct ports (potential port scan):

```kql
DeviceNetworkEvents
| where Timestamp > ago(10m)
| where ActionType == "ConnectionAttempt"   // TCP SYN sent, handshake not yet complete
| summarize Attempts = count(),
            DistinctPorts = dcount(RemotePort)
  by DeviceName, RemoteIP, bin(Timestamp, 1m)
| where Attempts > 100 or DistinctPorts > 20
| sort by Attempts desc
```
