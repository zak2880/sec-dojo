# Malleable C2 Profiles

- [ ] Read
- [ ] Reviewed KQL example
- [ ] Could explain this to someone else

## Why this matters for detection

Frameworks like Cobalt Strike can make beacon traffic look exactly like a jQuery CDN request or an Office365 API call — the [HTTP Request Anatomy](../03-http-tls/01-http-request-anatomy.md) checks you'd normally rely on stop working, but the [JA3](../03-http-tls/03-ja3-fingerprinting.md) fingerprint underneath often still gives it away.

## Core concept

- A **malleable C2 profile** is a config script that rewrites a beacon's HTTP URI, headers, and response format to mimic a real service — e.g. making a check-in look like `GET /jquery-3.3.1.min.js` against `code.jquery.com`, complete with matching headers and a decoy response body.
- This defeats HTTP-layer signature detection (odd URI, hardcoded User-Agent) because the traffic is deliberately crafted to match the exact legitimate request pattern, not just approximate it.
- The profile only rewrites what's visible **above TLS**. The TLS library actually doing the handshake (the OS default stack or a statically-linked one) still produces its own JA3 fingerprint — and that fingerprint rarely matches the real browser/client library that would normally make that HTTP request.
- Detection: correlate the HTTP-layer template match (URI/Host pattern resembling a known service) against the JA3 hash for that same connection — legitimate-looking request, illegitimate TLS client.

## Diagram

```
Beacon HTTP request (looks legit):
  GET /jquery-3.3.1.min.js HTTP/1.1
  Host: code.jquery.com
  User-Agent: Mozilla/5.0 ...        ← convincing at L7

TLS ClientHello underneath:
  JA3 = 6bea65e94c4b4b67d197a05f60d46f78  ← Cobalt Strike default, NOT a real browser
```

## KQL Example

> ⚠️ **Note:** Correlating the HTTP template against the TLS fingerprint needs both `http.log` and `ssl.log` from a Zeek sensor, joined on the shared connection `uid` — the same join pattern as the domain fronting lesson.

**Join-based hunt — legit-looking URI/Host, illegitimate JA3:**

```kql
let RealBrowserJA3 = datatable(hash: string)[
    "cd08e31494f9531f560d64c695473da9",   // Chrome
    "579ccef312d18482fc42e2b822ca2430"    // Firefox
];
Zeek_HTTP_CL
| where TimeGenerated > ago(24h)
| where host has_any ("code.jquery.com", "ajax.googleapis.com", "login.microsoftonline.com")
| join kind=inner (
    Zeek_SSL_CL
    | project uid, ja3
  ) on uid
| where ja3 !in (RealBrowserJA3)
  // HTTP layer looks legit, but the TLS client fingerprint doesn't match a real browser
| project TimeGenerated, id_orig_h, id_resp_h, host, uri, ja3
| sort by TimeGenerated desc
```

**Option B — MDE process pivot (weak substitute, no TLS fingerprint available):**

```kql
DeviceNetworkEvents
| where RemoteUrl has_any ("jquery.com", "ajax.googleapis.com", "login.microsoftonline.com")
| where InitiatingProcessFileName !in~ ("chrome.exe", "msedge.exe", "firefox.exe")
| summarize count() by InitiatingProcessFileName, RemoteUrl
| sort by count_ desc
```
