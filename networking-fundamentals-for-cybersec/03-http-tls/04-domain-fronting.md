# Domain Fronting

- [ ] Read
- [ ] Reviewed KQL example
- [ ] Could explain this to someone else

## Why this matters for detection

Domain fronting lets attacker traffic hide behind a domain your firewall already trusts — the block-by-domain control most orgs rely on never even sees the real destination.

## Core concept

- TLS sends the destination hostname twice: once in the **cleartext SNI** field of the ClientHello (what firewalls/proxies usually inspect), and again in the **encrypted HTTP `Host` header** once the session is up. These don't have to match.
- **Domain fronting** sets the SNI to a trusted, high-reputation CDN domain (e.g. a large CDN's edge domain) — which sails through allowlists — while the encrypted `Host` header names the attacker's actual backend. The CDN's edge routes the request by the `Host` header, not the SNI, delivering it to the real target anyway.
- Because the `Host` header is inside the TLS session, a passive network tap genuinely cannot see it — this technique only becomes detectable where you already have decrypted visibility (a TLS-inspecting forward proxy, or Zeek fed a `SSLKEYLOGFILE`).
- Most major CDN providers (Google, AWS CloudFront, Azure) patched routing-by-SNI-only behaviour after abuse reports (~2018), closing this off on their platforms — but it can still work against misconfigured or smaller CDNs that don't enforce SNI/Host consistency.

## Diagram

```
Client TLS ClientHello:   SNI = trusted-cdn.example        (cleartext, passes allowlist)
Client HTTP (encrypted):  Host: attacker-c2.herokuapp.com  (hidden inside the TLS session)
CDN edge routes by Host header → forwards to attacker's real backend
Firewall only ever saw "trusted-cdn.example" ✓ allowed
```

## KQL Example

> ⚠️ **Note:** The `Host` header is encrypted — this detection only works where you have decrypted visibility (TLS-inspecting proxy, or Zeek with decryption keys) so `http.log` captures the real `Host` separately from the cleartext SNI in `ssl.log`. Without that, only the SNI side is observable at all.

**Join-based hunt — SNI/Host mismatch on the same connection (Zeek `uid` correlates logs across `ssl.log` and `http.log` for one connection):**

```kql
Zeek_SSL_CL
| where TimeGenerated > ago(1h)
| project TimeGenerated, uid, id_orig_h, id_resp_h, sni_domain = server_name
| join kind=inner (
    Zeek_HTTP_CL
    | project uid, host_header = host
  ) on uid
| where sni_domain != host_header
| where sni_domain has_any ("cloudfront.net", "azureedge.net", "fastly.net")
  // narrow to known CDN edge domains commonly abused for fronting
| project TimeGenerated, id_orig_h, id_resp_h, sni_domain, host_header
| sort by TimeGenerated desc
```

Without decrypted visibility, treat this as a **conceptual two-step hunt** instead: (1) pull rare/first-seen SNI destinations to major CDN edge domains, (2) escalate any hit to your proxy team to check the corresponding decrypted `Host` header for that connection.
