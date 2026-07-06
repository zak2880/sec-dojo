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

Detect hosts generating large volumes of SYN-only connections (potential port scan):

```kql
NetworkCommunicationEvents
| where Protocol == "Tcp"
| summarize SynCount = countif(TcpFlags has "SYN"),
            AckCount = countif(TcpFlags has "ACK")
  by LocalIP, bin(Timestamp, 1m)
| where SynCount > 200 and AckCount < 10
```
