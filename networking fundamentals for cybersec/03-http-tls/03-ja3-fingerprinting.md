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

Match observed JA3 hashes against a known-bad list:

```kql
let BadJA3 = datatable(hash: string, label: string)[
    "e7d705a3286e19ea42f587b344ee6865", "Metasploit",
    "6bea65e94c4b4b67d197a05f60d46f78", "CobaltStrike-default"
];
DeviceNetworkEvents
| where isnotempty(JA3)
| join kind=inner BadJA3 on $left.JA3 == $right.hash
| project Timestamp, DeviceName, RemoteIP, RemotePort, label
```
