# Detecting Beacon Patterns with KQL

- [ ] Read
- [ ] Reviewed KQL example
- [ ] Could explain this to someone else

## Why this matters for detection

This is a practical, deployable hunting query — running it weekly against your environment finds implants that signature-based rules miss entirely.

## Core concept

- **Three signals together** make a strong beacon hypothesis: (1) regular inter-arrival time, (2) consistent small payload size, (3) connection to the same external IP/domain over an extended window.
- **Payload size consistency** is a powerful secondary check — beacon check-ins are tiny and uniform (e.g. always ~300 bytes). Exfil breaks this pattern with larger, variable payloads.
- Effective beacon hunting requires a **long time window** (24–72 h). Short windows miss long-sleep implants and give too few samples for meaningful statistics.

## Diagram

```
Beacon signature fingerprint:
  ┌─ Same RemoteIP/Port
  ├─ Regular interval (low StdDev)
  ├─ Small consistent SentBytes (~100–600 B)
  └─ High connection count over 24h+
```

## KQL Example

Full beacon hunter — regularity + payload size consistency over 24 hours:

```kql
let TimeWindow = 24h;
DeviceNetworkEvents
| where Timestamp > ago(TimeWindow)
| where RemoteIPType == "Public"
| where RemotePort in (80, 443, 8080, 8443, 53)
| sort by DeviceName, RemoteIP, RemotePort, Timestamp asc
| serialize
| extend PrevTime = prev(Timestamp, 1),
         PrevDevice = prev(DeviceName, 1),
         PrevRemote = prev(RemoteIP, 1)
| where DeviceName == PrevDevice and RemoteIP == PrevRemote
| extend IntervalSec = datetime_diff('second', Timestamp, PrevTime)
| summarize
    AvgInterval  = avg(IntervalSec),
    StdDev       = stdev(IntervalSec),
    AvgBytes     = avg(SentBytes),
    StdDevBytes  = stdev(SentBytes),
    Connections  = count()
  by DeviceName, RemoteIP, RemotePort
| where Connections > 15
| where StdDev < (AvgInterval * 0.3)    // interval variance < 30%
| where StdDevBytes < 200               // consistent payload size
| where AvgBytes < 1500                 // small payloads
| project DeviceName, RemoteIP, RemotePort,
          AvgInterval, StdDev, AvgBytes, Connections
| sort by StdDev asc
```
