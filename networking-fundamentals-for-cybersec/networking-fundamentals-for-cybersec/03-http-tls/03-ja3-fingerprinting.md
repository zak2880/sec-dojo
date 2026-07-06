# JA3 TLS Fingerprinting

- [ ] Read
- [ ] Reviewed KQL example
- [ ] Could explain this to someone else

## Why this matters for detection

JA3 hashes let you identify a specific TLS client library regardless of what domain it's connecting to — the same Cobalt Strike default profile produces the same hash across all beacons.

## Core concept

- **JA3** hashes five fields from the ClientHello: TLS version, cipher suites, extensions, elliptic curves, and elliptic curve point formats. The MD5 of their concatenation is the JA3 hash.
- **JA3S** does the same for the ServerHello. Pairing JA3 + JA3S fingerprints a specific client-server pair (e.g. a known C2 framework talking to its server).
- Known-bad JA3 hashes are shared publicly (e.g. `e7d705a3286e19ea42f587b344ee6865` = Metasploit). Matching your traffic against threat intel feeds is highly effective.

## Diagram

```
ClientHello fields → concatenate → MD5 hash = JA3
  TLSVersion,Ciphers,Extensions,EllipticCurves,PointFormats
  "771,4866-4867-...,0-23-...,29-23-...,0" → md5 → abc123...
```

## KQL Example

> ⚠️ **Note:** JA3/JA3S metadata is not natively captured in `DeviceNetworkEvents`. This requires a network sensor feed (e.g. Zeek, Suricata, Corelight) ingested into a custom Sentinel table.

**Option A — Zeek `ssl.log` ingested as `Zeek_SSL_CL`:**

Match JA3 hashes against a known-bad threat intel list:

```kql
let BadJA3 = datatable(hash: string, label: string)[
    "e7d705a3286e19ea42f587b344ee6865", "Metasploit",
    "6bea65e94c4b4b67d197a05f60d46f78", "CobaltStrike-default",
    "51c64c77e60f3980eea90869b68c58a8", "CobaltStrike-malleable"
];
Zeek_SSL_CL
| where TimeGenerated > ago(24h)
| where isnotempty(ja3)
| join kind=inner BadJA3 on $left.ja3 == $right.hash
| project TimeGenerated, id_orig_h, id_resp_h, id_resp_p,
          server_name, ja3, ja3s, label
```

**Option B — MDE `DeviceNetworkEvents` (connection pivot only):**

No JA3 available natively, but you can pivot on process + destination patterns as a starting point:

```kql
DeviceNetworkEvents
| where RemotePort in (443, 8443, 4443)
| where InitiatingProcessFileName !in ("chrome.exe", "msedge.exe", "firefox.exe", "Teams.exe")
| summarize count() by InitiatingProcessFileName, RemoteIP, RemotePort
| sort by count_ desc
```
