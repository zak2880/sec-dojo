# DNS-over-HTTPS / DNS-over-TLS as a Detection Blind Spot

- [ ] Read
- [ ] Reviewed KQL example
- [ ] Could explain this to someone else

## Why this matters for detection

Every DNS detection covered so far — tunnelling, DGA, fast-flux — depends on seeing the query. DoH/DoT moves that query somewhere your DNS logs can't see it at all.

## Core concept

- **DoH (RFC 8484)** wraps a DNS query inside a normal HTTPS request, typically to a `/dns-query` endpoint on port 443. To a network monitor, it's indistinguishable from any other HTTPS traffic to that host.
- **DoT (RFC 7858)** wraps DNS in TLS on a dedicated port (853) — easier to block by port, but the query content is still hidden from inspection.
- Many browsers and OSes now default to DoH against public resolvers: **Cloudflare** (`1.1.1.1`, `cloudflare-dns.com`), **Google** (`8.8.8.8`, `dns.google`), **Quad9** (`9.9.9.9`, `dns.quad9.net`). Malware can piggyback on the same trusted resolvers or stand up its own DoH endpoint.
- Since the query never reaches the traditional stub resolver, `DnsEvents` sees nothing. Detection degrades to two weaker network-layer signals: matching connections against known DoH resolver IPs/domains (easily evaded with a custom resolver), and JA3-fingerprinting the TLS client library DoH tools use (see [JA3 TLS Fingerprinting](../03-http-tls/03-ja3-fingerprinting.md)).

## Diagram

```
Before DoH:  Endpoint → UDP/53 → Corp Resolver → visible in DnsEvents

With DoH:    Endpoint → TLS/443 → doh.provider.com/dns-query
                        (looks identical to any other HTTPS request)
```

## KQL Example

> ⚠️ **Note:** Once DNS moves inside HTTPS/TLS, `DnsEvents` has nothing to show. Detection has to fall back to connection metadata (`DeviceNetworkEvents`) and, where available, TLS client fingerprinting from a sensor feed.

**Option A — known DoH resolver IPs/domains (MDE-native, weakest but zero setup):**

```kql
DeviceNetworkEvents
| where RemotePort == 443
| where RemoteUrl has_any ("cloudflare-dns.com", "dns.google", "dns.quad9.net")
       or RemoteIP in ("1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9")
| where InitiatingProcessFileName !in~ ("chrome.exe", "msedge.exe", "firefox.exe")
  // browsers legitimately speak DoH to these resolvers by default; non-browser callers are the interesting case
| project Timestamp, DeviceName, RemoteUrl, RemoteIP, InitiatingProcessFileName
| sort by Timestamp desc
```

**Option B — JA3 match against known DoH client libraries (Zeek sensor, ties back to the JA3 lesson):**

A custom DoH endpoint won't match Option A's IP/domain list at all — but the small set of libraries used to build DoH clients (`cloudflared`, `curl --doh-url`, `dnscrypt-proxy`) still produce recognisable JA3 hashes regardless of destination:

```kql
let DoHClientJA3 = datatable(hash: string, label: string)[
    "91010b75e75ab015928692263cc8b889", "cloudflared (DoH client)",
    "cd1220edee7a9e0495ca56c8fe45f0cf", "curl --doh-url",
    "68c50641e5dda4b7c93435bf66e31d24", "dnscrypt-proxy"
];
Zeek_SSL_CL
| where TimeGenerated > ago(24h)
| where isnotempty(ja3)
| join kind=inner DoHClientJA3 on $left.ja3 == $right.hash
| project TimeGenerated, id_orig_h, id_resp_h, server_name, ja3, label
| sort by TimeGenerated desc
```
