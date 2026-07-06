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

Flag connections using self-signed or short-lived certificates:

```kql
DeviceNetworkEvents
| where RemotePort == 443
| where isnotempty(SslSubject)
| where SslIssuer == SslSubject   // self-signed: issuer == subject
| summarize count() by RemoteIP, SslSubject, DeviceName
| sort by count_ desc
```
