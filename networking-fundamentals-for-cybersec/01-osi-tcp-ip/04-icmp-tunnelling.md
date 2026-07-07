# ICMP & ICMP Tunnelling

- [ ] Read
- [ ] Reviewed KQL example
- [ ] Could explain this to someone else

## Why this matters for detection

ICMP is treated as diagnostic "background noise" by most tooling, so it's rarely inspected — making it a quiet channel for C2 and exfiltration that most security stacks never look at.

## Core concept

- **Normal ICMP**: echo request/reply (ping), destination unreachable, time exceeded (traceroute), redirect. No ports, no session state — just control-plane messages between hosts and routers.
- Because ICMP carries no port numbers and is usually allowed outbound by default (it's needed for path MTU discovery and basic diagnostics), firewalls and proxies rarely filter or log it the way they do TCP/UDP.
- Tools like **icmpsh**, **ptunnel**, and **icmptunnel** abuse the **data payload field** of echo request/reply packets — which has no defined format or size limit beyond MTU — to carry arbitrary C2 commands or exfiltrated data instead of the usual fixed diagnostic pattern.
- Key indicators: standard OS pings send small, fixed-size payloads (Windows default 32 bytes, Linux default 56 bytes). Tunnelling tools push payloads far larger and send far more frequently than any diagnostic ping ever would.

## Diagram

```
Normal ping:   Echo Request (32-56B payload) → Echo Reply (32-56B payload)
                  ...one-off, low frequency

ICMP tunnel:   Echo Request (1400B payload: "cmd: whoami")
               Echo Reply   (1400B payload: exfiltrated output)
               ...repeated every few seconds, sustained volume
```

## KQL Example

> ⚠️ **Note:** `DeviceNetworkEvents` is connection/socket-based and does not capture raw ICMP traffic or payload sizes. This requires a network sensor (e.g. Zeek, Suricata) with a tap or SPAN port, ingested into a custom Sentinel table.

**Option A — Zeek `conn.log` ingested as `Zeek_Conn_CL` (oversized payload):**

Flag ICMP traffic carrying far more data than a standard ping:

```kql
Zeek_Conn_CL
| where TimeGenerated > ago(24h)
| where proto == "icmp"
| where orig_bytes > 64   // standard ping payload is 32-56 bytes; tunnelling pushes far more
| project TimeGenerated, id_orig_h, id_resp_h, orig_bytes, resp_bytes, duration
| sort by orig_bytes desc
```

**Option B — Zeek `conn.log` (volume, same table):**

Diagnostic pings are sporadic and manual; a tunnel sustains steady traffic. Flag hosts exchanging a high count of ICMP packets with the same destination in a short window:

```kql
Zeek_Conn_CL
| where TimeGenerated > ago(1h)
| where proto == "icmp"
| summarize IcmpCount = count(), AvgBytes = avg(orig_bytes)
  by id_orig_h, id_resp_h, bin(TimeGenerated, 5m)
| where IcmpCount > 100
| sort by IcmpCount desc
```

**Option C — MDE process-command-line pivot (no packet visibility, catches manual misuse):**

MDE won't see the ICMP traffic itself, but `ping.exe` invoked with a custom payload size (`-l`) is a visible precursor worth flagging — legitimate use rarely sets a payload anywhere near the 65500-byte maximum:

```kql
DeviceProcessEvents
| where FileName in~ ("ping.exe", "ping")
| where ProcessCommandLine has "-l "
| extend SizeArg = extract(@"-l\s+(\d+)", 1, ProcessCommandLine)
| where isnotempty(SizeArg) and toint(SizeArg) > 1000
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
| sort by Timestamp desc
```
