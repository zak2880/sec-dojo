# What is Beaconing?

- [ ] Read
- [ ] Reviewed KQL example
- [ ] Could explain this to someone else

## Why this matters for detection

Beaconing is the heartbeat of almost every post-exploitation framework — if you can find the pattern, you find the implant.

## Core concept

- **Beaconing** is when an implant periodically contacts its C2 server to check for new commands. The implant initiates the connection (outbound) to avoid firewall blocks on inbound connections.
- A standard beacon sends a small HTTP/S or DNS request every N seconds/minutes, receives a command or a "nothing to do" response, and sleeps until the next interval.
- Common frameworks and their defaults: **Cobalt Strike** (60 s), **Metasploit Meterpreter** (varies), **Sliver** (60 s). Analysts hunt beacons by looking for **statistically regular connection intervals** to external IPs.

## Diagram

```
Implant → C2 server (check-in every 60 s)
t=0s:   POST /updates → 200 OK "no task"
t=60s:  POST /updates → 200 OK "no task"
t=120s: POST /updates → 200 OK [cmd: whoami]
t=180s: POST /updates → 200 OK "no task"
```

## KQL Example

Find hosts making periodic outbound connections to the same external IP:

```kql
DeviceNetworkEvents
| where RemoteIPType == "Public"
| summarize ConnectionCount = count(), 
            FirstSeen = min(Timestamp),
            LastSeen = max(Timestamp)
  by DeviceName, RemoteIP, RemotePort
| extend Duration = datetime_diff('minute', LastSeen, FirstSeen)
| where ConnectionCount > 20 and Duration > 30
| where RemotePort in (80, 443, 8080, 8443)
```
