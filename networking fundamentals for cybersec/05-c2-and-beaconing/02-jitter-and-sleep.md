# Jitter and Sleep Intervals

- [ ] Read
- [ ] Reviewed KQL example
- [ ] Could explain this to someone else

## Why this matters for detection

Jitter is specifically designed to defeat time-based beacon detection — knowing how it works lets you adjust your analytics to find it anyway.

## Core concept

- **Jitter** adds randomness to the sleep interval so beacons don't fire at exactly regular intervals. Cobalt Strike's `sleep 60 25` means "sleep 60 s ± 25% random variance" → actual intervals between ~45 s and 75 s.
- Without jitter the beacon is trivial to detect (exact periodicity). With jitter, simple `count by interval` queries fail. You need **statistical analysis**: standard deviation of inter-arrival times, or clustering.
- **Long sleep** ("low and slow") means intervals of hours or days to evade time-window-based detection. The implant may only check in once per day, making volume-based rules useless.

## Diagram

```
No jitter:   60s──60s──60s──60s  (obvious spike at 60 s in time analysis)
25% jitter:  47s──71s──58s──63s  (spread, harder to spot)
Long sleep:  8h──────8h──────8h  (falls outside alert windows)
```

## KQL Example

Use standard deviation to find near-regular (jittered) beacons:

```kql
DeviceNetworkEvents
| where RemoteIPType == "Public"
| sort by DeviceName, RemoteIP, Timestamp asc
| serialize
| extend PrevTime = prev(Timestamp, 1)
| where isnotempty(PrevTime)
| extend IntervalSec = datetime_diff('second', Timestamp, PrevTime)
| summarize AvgInterval = avg(IntervalSec),
            StdDev = stdev(IntervalSec),
            Samples = count()
  by DeviceName, RemoteIP
| where Samples > 10 and StdDev < 30 and AvgInterval between (30 .. 3600)
| sort by StdDev asc
```
