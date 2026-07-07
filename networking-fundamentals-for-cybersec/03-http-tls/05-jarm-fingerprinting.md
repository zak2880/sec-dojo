# JARM Server Fingerprinting

- [ ] Read
- [ ] Reviewed KQL example
- [ ] Could explain this to someone else

## Why this matters for detection

[JA3](03-ja3-fingerprinting.md) fingerprints the client talking to a server. JARM flips that around — it fingerprints the C2 server itself, so it still identifies known-bad infrastructure even when every client hitting it has a different (or clean) JA3.

## Core concept

- JARM works by sending **10 crafted TLS ClientHellos** to a target, each varying TLS version, cipher order, and extensions. The target's TLS stack responds differently to each depending on its configuration.
- The 10 **ServerHello responses** are concatenated and hashed into a single 62-character **JARM hash** — a fingerprint of the server's TLS stack configuration, not any one client's.
- This is useful because a C2 server's TLS stack config tends to stay constant across the lifetime of that infrastructure, even as operators rotate domains/IPs or redeploy the malware client with a different build. Researchers share known-bad JARM hashes for default configs of common frameworks (Cobalt Strike, Sliver, Mythic) the same way JA3 blocklists work.
- JARM requires **active probing** — 10 handshakes per target — so it's typically run as a scanning pipeline against externally-observed IPs (your own scanner, or ingesting scan-data feeds), not derived passively from traffic like JA3.

## Diagram

```
Scanner → 10x crafted ClientHellos (varying version/cipher order/extensions) → Target:443
Target's 10 ServerHello responses → concatenated → JARM hash (62 hex chars)
Same backend TLS stack = same JARM, regardless of which client or domain hits it
```

## KQL Example

> ⚠️ **Note:** JARM isn't captured by passive sensors (Zeek doesn't compute it natively) — it comes from a separate active-scanning pipeline whose results you ingest into a custom Sentinel table.

**Option A — known-bad JARM match (threat intel join, same pattern as the JA3 lesson):**

```kql
let BadJARM = datatable(hash: string, label: string)[
    "a729330cc0bf8f6abfc81b1f57f72dc8cbe31b9e5e8924be29088a3153329a", "CobaltStrike-default-jarm",
    "5cad0f13cee08c4c99fd32a83b589c4d8944cc6646d0ab76f64e23c076d311", "Sliver-default-jarm",
    "e7e6a678291e807ada77552ab13083ef98e91497b99cf9c88e4767529b0d63", "Mythic-default-jarm"
];
JarmScan_CL
| where TimeGenerated > ago(24h)
| where isnotempty(jarm)
| join kind=inner BadJARM on $left.jarm == $right.hash
| project TimeGenerated, dest_ip, dest_port, jarm, label
| sort by TimeGenerated desc
```

**Option B — MDE queue-builder pivot (no JARM itself, but feeds new destinations into your scanner):**

There's no passive MDE-native JARM detection — JARM needs active probing — but you can use rare/first-seen public HTTPS destinations to decide what to scan next:

```kql
DeviceNetworkEvents
| where RemotePort == 443 and RemoteIPType == "Public"
| where ActionType == "ConnectionSuccess"
| summarize FirstSeen = min(Timestamp), Connections = count() by RemoteIP
| where FirstSeen > ago(24h) and Connections < 10   // new, low-volume destinations worth JARM-scanning
| sort by FirstSeen desc
```
