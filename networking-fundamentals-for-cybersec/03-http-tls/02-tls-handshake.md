# TLS Handshake

- [ ] Read
- [ ] Reviewed KQL example
- [ ] Could explain this to someone else

## Why this matters for detection

You can't decrypt TLS traffic without the key, but the handshake metadata — cipher suites, extensions, certificate details — fingerprints clients and reveals malware using self-signed certs.

## Core concept

- **Handshake steps (TLS 1.3 simplified)**: ClientHello → ServerHello → Server Certificate + Finished → Client Finished → Encrypted application data.
- The **ClientHello** contains: TLS version, supported cipher suites, and extensions (SNI, ALPN, supported groups). This unencrypted metadata is what JA3 hashes.
- Watch for: **self-signed or expired certificates**, certificates with IP addresses as the Subject CN, mismatches between the SNI hostname and the certificate's Common Name.

## Diagram

```
Client                          Server
  |--- ClientHello ------------->|  (cipher suites, SNI, extensions)
  |<-- ServerHello + Cert -------|  (chosen cipher, certificate)
  |--- Verify cert, Finished --->|
  |<-- Finished -----------------|
  |======= Encrypted data ======|
```

## KQL Example

> ⚠️ **Note:** Certificate metadata (`SslSubject`, `SslIssuer`) is not natively captured in `DeviceNetworkEvents`. This requires a network sensor feed (e.g. Zeek, Suricata, Corelight) ingested into a custom Sentinel table.

**Option A — Zeek `ssl.log` ingested as `Zeek_SSL_CL`:**

Flag self-signed certificates observed by your Zeek sensor:

```kql
Zeek_SSL_CL
| where TimeGenerated > ago(24h)
| where isnotempty(subject) and isnotempty(issuer)
| where subject == issuer   // self-signed: issuer matches subject
| project TimeGenerated, id_orig_h, id_resp_h, id_resp_p,
          server_name, subject, issuer, validation_status
| sort by TimeGenerated desc
```

**Option B — MDE `DeviceNetworkEvents` (connection-level only, no cert metadata):**

Spot unusual TLS destinations as a starting pivot before pivoting to sensor data:

```kql
DeviceNetworkEvents
| where RemotePort == 443 and RemoteIPType == "Public"
| where ActionType == "ConnectionSuccess"
| summarize Connections = count(), firstSeen = min(Timestamp)
  by DeviceName, RemoteIP
| where Connections < 5   // rare destinations worth reviewing
| sort by firstSeen asc
```
