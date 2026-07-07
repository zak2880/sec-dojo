# KQL Patterns Library

A single quick-reference of every KQL query taught across the sec-dojo networking-fundamentals lessons, organized by detection technique rather than by networking topic. Each entry links back to the lesson that explains the underlying theory.

Most queries target Microsoft Defender for Endpoint's `DeviceNetworkEvents` / `DnsEvents` tables. Where the detection needs metadata MDE doesn't capture natively (ARP frames, certificate fields, JA3 hashes, switch syslog), the query targets a network-sensor table (Zeek logs ingested as custom `_CL` tables) or `CommonSecurityLog` instead — noted per entry.

---

## Beaconing & C2

### Periodic outbound connections (baseline)
Detects hosts making a high number of repeated outbound connections to the same external IP/port over a rolling window — the simplest beacon signal, before accounting for jitter.
```kql
DeviceNetworkEvents
| where RemoteIPType == "Public"
| summarize ConnectionCount = count(), 
            FirstSeen = min(Timestamp),
            LastSeen = max(Timestamp)
  by DeviceName, RemoteIP, RemotePort
| extend Duration = datetime_diff('minute', LastSeen, FirstSeen)
| where ConnectionCount > 20 and Duration > 30
| where RemotePort in (80, 443, 8080, 8443)
```
Source: [05-c2-and-beaconing/01-what-is-beaconing.md](05-c2-and-beaconing/01-what-is-beaconing.md)

### DNS-based beaconing (attack variant)
Applies the same periodicity hypothesis to `DnsEvents` — catches implants that check in via periodic DNS queries instead of HTTP/S.
```kql
DnsEvents
| where TimeGenerated > ago(24h)
| summarize QueryCount = count(),
            FirstSeen = min(TimeGenerated),
            LastSeen = max(TimeGenerated)
  by ClientIP, Name
| extend Duration = datetime_diff('minute', LastSeen, FirstSeen)
| where QueryCount > 50 and Duration > 60
| sort by QueryCount desc
```
Source: [05-c2-and-beaconing/01-what-is-beaconing.md](05-c2-and-beaconing/01-what-is-beaconing.md)

### Jittered beacon detection (statistical)
Uses standard deviation of inter-arrival times to catch beacons that add random jitter to their sleep interval and would evade a naive fixed-interval check.
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
Source: [05-c2-and-beaconing/02-jitter-and-sleep.md](05-c2-and-beaconing/02-jitter-and-sleep.md)

### Jittered beacon detection, fleet-rarity tuned
Same stdev hypothesis, but excludes destinations contacted by many devices fleet-wide — cuts false positives from legitimate shared polling (SaaS heartbeats, update checks) that a lone-implant C2 IP wouldn't produce.
```kql
DeviceNetworkEvents
| where RemoteIPType == "Public"
| sort by DeviceName, RemoteIP, Timestamp asc
| serialize
| extend PrevTime = prev(Timestamp, 1), PrevDevice = prev(DeviceName, 1), PrevRemote = prev(RemoteIP, 1)
| where DeviceName == PrevDevice and RemoteIP == PrevRemote
| extend IntervalSec = datetime_diff('second', Timestamp, PrevTime)
| summarize AvgInterval = avg(IntervalSec), StdDev = stdev(IntervalSec), Samples = count()
  by DeviceName, RemoteIP
| where Samples > 10 and StdDev < 30 and AvgInterval between (30 .. 3600)
| join kind=leftanti (
    DeviceNetworkEvents
    | where RemoteIPType == "Public"
    | summarize DeviceCount = dcount(DeviceName) by RemoteIP
    | where DeviceCount > 5   // touched by more than 5 hosts = likely shared/legitimate service
  ) on RemoteIP
| sort by StdDev asc
```
Source: [05-c2-and-beaconing/02-jitter-and-sleep.md](05-c2-and-beaconing/02-jitter-and-sleep.md)

### Full beacon hunter (tuned, reduced false positives)
Combines interval regularity with payload-size consistency over a 24h window — the strongest single beacon hypothesis, and the version most suitable to run as a scheduled hunt.
```kql
let TimeWindow = 24h;
DeviceNetworkEvents
| where Timestamp > ago(TimeWindow)
| where RemoteIPType == "Public"
| where RemotePort in (80, 443, 8080, 8443, 53)
| sort by DeviceName, RemoteIP, RemotePort, Timestamp asc
| serialize
| extend PrevTime = prev(Timestamp, 1),
         PrevDevice = prev(DeviceName, 1),
         PrevRemote = prev(RemoteIP, 1)
| where DeviceName == PrevDevice and RemoteIP == PrevRemote
| extend IntervalSec = datetime_diff('second', Timestamp, PrevTime)
| summarize
    AvgInterval  = avg(IntervalSec),
    StdDev       = stdev(IntervalSec),
    AvgBytes     = avg(SentBytes),
    StdDevBytes  = stdev(SentBytes),
    Connections  = count()
  by DeviceName, RemoteIP, RemotePort
| where Connections > 15
| where StdDev < (AvgInterval * 0.3)    // interval variance < 30%
| where StdDevBytes < 200               // consistent payload size
| where AvgBytes < 1500                 // small payloads
| project DeviceName, RemoteIP, RemotePort,
          AvgInterval, StdDev, AvgBytes, Connections
| sort by StdDev asc
```
Source: [05-c2-and-beaconing/03-detecting-beacon-patterns-kql.md](05-c2-and-beaconing/03-detecting-beacon-patterns-kql.md)

### Low-and-slow beacon hunter (7-day window)
Same regularity + payload-consistency hunter, widened to a 7-day window with a lower connection-count floor — catches implants that check in only a handful of times per week, which the 24h version misses.
```kql
let TimeWindow = 7d;
DeviceNetworkEvents
| where Timestamp > ago(TimeWindow)
| where RemoteIPType == "Public"
| where RemotePort in (80, 443, 8080, 8443, 53)
| sort by DeviceName, RemoteIP, RemotePort, Timestamp asc
| serialize
| extend PrevTime = prev(Timestamp, 1),
         PrevDevice = prev(DeviceName, 1),
         PrevRemote = prev(RemoteIP, 1)
| where DeviceName == PrevDevice and RemoteIP == PrevRemote
| extend IntervalSec = datetime_diff('second', Timestamp, PrevTime)
| summarize
    AvgInterval  = avg(IntervalSec),
    StdDev       = stdev(IntervalSec),
    AvgBytes     = avg(SentBytes),
    StdDevBytes  = stdev(SentBytes),
    Connections  = count()
  by DeviceName, RemoteIP, RemotePort
| where Connections between (3 .. 15)   // low-and-slow: few connections over a long window
| where AvgInterval > 3600              // average interval > 1 hour
| where StdDev < (AvgInterval * 0.3)
| where StdDevBytes < 200
| project DeviceName, RemoteIP, RemotePort,
          AvgInterval, StdDev, AvgBytes, Connections
| sort by AvgInterval desc
```
Source: [05-c2-and-beaconing/03-detecting-beacon-patterns-kql.md](05-c2-and-beaconing/03-detecting-beacon-patterns-kql.md)

### Rare / hardcoded User-Agent strings (C2 check-in indicator)
Flags uncommon User-Agent + destination combinations in proxy logs — malware implants frequently hardcode a static User-Agent for their check-in requests.
```kql
DeviceNetworkEvents
| where RemotePort in (80, 443, 8080)
| summarize count() by InitiatingProcessFileName, RemoteUrl
| where count_ < 5
| sort by count_ asc
```
Source: [03-http-tls/01-http-request-anatomy.md](03-http-tls/01-http-request-anatomy.md)

### Non-approved process reaching a SaaS API (baseline)
Flags connections to trusted SaaS domains (Slack, Discord, Dropbox, GitHub) coming from anything other than the browser or the platform's own desktop app — the behavioral pivot needed once C2 hides behind a domain that can't be blocklisted.
```kql
DeviceNetworkEvents
| where RemoteUrl has_any ("slack.com", "discord.com", "discordapp.com", "api.dropboxapi.com", "github.com")
| where InitiatingProcessFileName !in~ ("chrome.exe", "msedge.exe", "firefox.exe", "Slack.exe", "Discord.exe", "OneDrive.exe")
| summarize count(), FirstSeen = min(Timestamp) by DeviceName, InitiatingProcessFileName, RemoteUrl
| sort by FirstSeen desc
```
Source: [05-c2-and-beaconing/04-c2-legitimate-services.md](05-c2-and-beaconing/04-c2-legitimate-services.md)

### Non-approved process reaching a SaaS API, fleet-rarity tuned
Same SaaS-abuse hypothesis, narrowed to processes/destinations touched by only one or two hosts — cuts false positives from legitimate fleet-wide automation (CI bots, sanctioned integrations) that a lone implant's C2 channel wouldn't produce.
```kql
DeviceNetworkEvents
| where RemoteUrl has_any ("slack.com", "discord.com", "discordapp.com", "api.dropboxapi.com", "github.com")
| where InitiatingProcessFileName !in~ ("chrome.exe", "msedge.exe", "firefox.exe", "Slack.exe", "Discord.exe", "OneDrive.exe")
| summarize Hosts = dcount(DeviceName), Connections = count() by InitiatingProcessFileName, RemoteUrl
| where Hosts <= 2   // sanctioned automation usually runs fleet-wide or from a known service account, not 1-2 endpoints
| sort by Connections desc
```
Source: [05-c2-and-beaconing/04-c2-legitimate-services.md](05-c2-and-beaconing/04-c2-legitimate-services.md)

### Malleable profile HTTP/JA3 mismatch (Zeek join)
Correlates a beacon's convincingly-templated HTTP URI/Host against the TLS client JA3 for the same connection — the HTTP layer can be disguised as a real service, but the underlying TLS stack fingerprint rarely matches the client library that service actually expects.
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
| project TimeGenerated, id_orig_h, id_resp_h, host, uri, ja3
| sort by TimeGenerated desc
```
Source: [05-c2-and-beaconing/05-malleable-c2-profiles.md](05-c2-and-beaconing/05-malleable-c2-profiles.md)

---

## DNS Anomalies & Exfiltration

### Short-TTL domains (DGA / fast-flux red flag)
Finds endpoints resolving domains with abnormally short TTLs — a fast-flux/DGA tactic to rotate IPs quickly and dodge blocklists.
```kql
DnsEvents
| where QueryType == "A"
| where TTL < 60 and TTL > 0
| summarize count() by Name, ClientIP
| sort by count_ desc
```
Source: [02-dns/01-dns-resolution-basics.md](02-dns/01-dns-resolution-basics.md)

### Long subdomain queries (DNS tunnelling)
Detects abnormally long subdomain labels and high per-domain query volume — the classic signature of DNS tunnelling tools like Iodine or DNScat2.
```kql
DnsEvents
| extend SubdomainLength = strlen(extract("^([^.]+)\.", 1, Name))
| where SubdomainLength > 50
| summarize count(), dcount(Name) by ClientIP, bin(TimeGenerated, 1h)
| where count_ > 20
```
Source: [02-dns/02-dns-tunneling.md](02-dns/02-dns-tunneling.md)

### Abnormal TXT-record query volume (DNS tunnelling variant)
Catches tunnelling tools that lean on frequent TXT-record lookups to carry command data rather than encoding everything in long subdomains.
```kql
DnsEvents
| where QueryType == "TXT"
| summarize TxtQueries = count(), DistinctDomains = dcount(Name)
  by ClientIP, bin(TimeGenerated, 1h)
| where TxtQueries > 100
| sort by TxtQueries desc
```
Source: [02-dns/02-dns-tunneling.md](02-dns/02-dns-tunneling.md)

### Oversized UDP/53 payloads (tunnelling, baseline broad)
Flags any DNS-port UDP packet larger than a standard query/response — a broad, low-effort tripwire for tunnelling traffic before applying entropy/volume analysis.
```kql
DeviceNetworkEvents
| where Timestamp > ago(24h)
| where Protocol == "Udp" and RemotePort == 53
| where SentBytes > 512   // standard DNS query rarely exceeds 512 bytes
| project Timestamp, DeviceName, RemoteIP, SentBytes, InitiatingProcessFileName
| sort by SentBytes desc
```
Source: [01-osi-tcp-ip/03-udp-vs-tcp.md](01-osi-tcp-ip/03-udp-vs-tcp.md)

### NXDOMAIN storms (DGA detection)
Flags hosts failing DNS resolution for dozens of unique domains in a short window — the signature of malware iterating through an algorithmically generated domain list.
```kql
DnsEvents
| where ResultCode == "NXDOMAIN"
| summarize FailedDomains = dcount(Name), TotalQueries = count()
  by ClientIP, bin(TimeGenerated, 10m)
| where FailedDomains > 50
| sort by FailedDomains desc
```
Source: [02-dns/03-dga-detection.md](02-dns/03-dga-detection.md)

---

## DNS Evasion

### Known DoH resolver IPs/domains (MDE-native)
Flags non-browser processes connecting to well-known public DoH resolvers (Cloudflare, Google, Quad9) — the weakest but zero-setup starting point once DNS moves inside HTTPS.
```kql
DeviceNetworkEvents
| where RemotePort == 443
| where RemoteUrl has_any ("cloudflare-dns.com", "dns.google", "dns.quad9.net")
       or RemoteIP in ("1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9")
| where InitiatingProcessFileName !in~ ("chrome.exe", "msedge.exe", "firefox.exe")
| project Timestamp, DeviceName, RemoteUrl, RemoteIP, InitiatingProcessFileName
| sort by Timestamp desc
```
Source: [02-dns/04-doh-dot-blindspot.md](02-dns/04-doh-dot-blindspot.md)

### DoH client JA3 match (Zeek sensor, ties to JA3 lesson)
Matches observed JA3 hashes against known DoH client libraries (`cloudflared`, `curl --doh-url`, `dnscrypt-proxy`) — catches custom DoH endpoints that Option A's IP/domain list would miss entirely.
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
Source: [02-dns/04-doh-dot-blindspot.md](02-dns/04-doh-dot-blindspot.md)

### Fast-flux: domain resolving to many distinct IPs (single-flux)
Flags a single domain resolving to an unusually high number of distinct IPs within a short window — the rotating-bot-pool signature of single-flux, distinct from DGA's many-domains-one-IP pattern.
```kql
DnsEvents
| where TimeGenerated > ago(1h)
| where QueryType == "A"
| summarize DistinctIPs = dcount(IPAddress), Resolutions = count()
  by Name, bin(TimeGenerated, 10m)
| where DistinctIPs > 15
| sort by DistinctIPs desc
```
Source: [02-dns/05-fast-flux-dns.md](02-dns/05-fast-flux-dns.md)

### Fast-flux: rotating nameservers (double-flux)
Applies the same distinct-count hypothesis to NS lookups — catches double-flux, where the A records may look comparatively stable while the authoritative nameserver delegation itself churns.
```kql
DnsEvents
| where TimeGenerated > ago(1h)
| where QueryType == "NS"
| summarize DistinctNS = dcount(IPAddress), Resolutions = count()
  by Name, bin(TimeGenerated, 30m)
| where DistinctNS > 5
| sort by DistinctNS desc
```
Source: [02-dns/05-fast-flux-dns.md](02-dns/05-fast-flux-dns.md)

---

## TLS / Certificate Anomalies & Fingerprinting

### Self-signed certificate detection (Zeek sensor)
Flags TLS connections presenting a certificate where issuer equals subject — a strong self-signed-cert indicator commonly seen with malware C2 infrastructure.
```kql
Zeek_SSL_CL
| where TimeGenerated > ago(24h)
| where isnotempty(subject) and isnotempty(issuer)
| where subject == issuer   // self-signed: issuer matches subject
| project TimeGenerated, id_orig_h, id_resp_h, id_resp_p,
          server_name, subject, issuer, validation_status
| sort by TimeGenerated desc
```
Source: [03-http-tls/02-tls-handshake.md](03-http-tls/02-tls-handshake.md)

### Rare public TLS destinations (MDE pivot, no cert metadata)
A starting pivot for environments without a sensor feed — surfaces low-frequency public HTTPS destinations worth manual review before escalating to full cert inspection.
```kql
DeviceNetworkEvents
| where RemotePort == 443 and RemoteIPType == "Public"
| where ActionType == "ConnectionSuccess"
| summarize Connections = count(), firstSeen = min(Timestamp)
  by DeviceName, RemoteIP
| where Connections < 5   // rare destinations worth reviewing
| sort by firstSeen asc
```
Source: [03-http-tls/02-tls-handshake.md](03-http-tls/02-tls-handshake.md)

### Known-bad JA3 hash match (threat intel join)
Joins observed JA3 hashes against a known-bad list to catch specific C2 frameworks (Cobalt Strike, Metasploit) regardless of destination domain or IP.
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
Source: [03-http-tls/03-ja3-fingerprinting.md](03-http-tls/03-ja3-fingerprinting.md)

### Non-browser TLS process pivot (MDE, no JA3 available)
Without native JA3 support, pivots on which processes are opening TLS-like connections outside known browser binaries — a coarse fingerprinting substitute.
```kql
DeviceNetworkEvents
| where RemotePort in (443, 8443, 4443)
| where InitiatingProcessFileName !in ("chrome.exe", "msedge.exe", "firefox.exe", "Teams.exe")
| summarize count() by InitiatingProcessFileName, RemoteIP, RemotePort
| sort by count_ desc
```
Source: [03-http-tls/03-ja3-fingerprinting.md](03-http-tls/03-ja3-fingerprinting.md)

### Rare / first-seen JA3 hash (baseline anomaly, no IOC dependency)
Flags JA3 hashes seen from only one host, a handful of times, over a longer window — surfaces novel or custom C2 tooling that a known-bad-list match would miss entirely.
```kql
Zeek_SSL_CL
| where TimeGenerated > ago(7d)
| where isnotempty(ja3)
| summarize FirstSeen = min(TimeGenerated), Hosts = dcount(id_orig_h), Connections = count()
  by ja3
| where Hosts == 1 and Connections < 5   // hash used by exactly one host, only a handful of times
| sort by FirstSeen desc
```
Source: [03-http-tls/03-ja3-fingerprinting.md](03-http-tls/03-ja3-fingerprinting.md)

---

## TLS/C2 Evasion

### Domain fronting: SNI/Host mismatch (Zeek join)
Correlates the cleartext SNI from `ssl.log` against the encrypted Host header from `http.log` for the same connection (`uid`) — flags traffic that passed a domain allowlist via SNI but actually routed to a different backend.
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
| project TimeGenerated, id_orig_h, id_resp_h, sni_domain, host_header
| sort by TimeGenerated desc
```
Source: [03-http-tls/04-domain-fronting.md](03-http-tls/04-domain-fronting.md)

### Known-bad JARM hash match (active-scan threat intel join)
Matches server JARM hashes (from a JARM-scanning pipeline) against known-bad C2 framework defaults — the server-side counterpart to the JA3 known-bad join, useful because a C2 server's TLS stack config stays constant even as the client-side JA3 changes across builds.
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
Source: [03-http-tls/05-jarm-fingerprinting.md](03-http-tls/05-jarm-fingerprinting.md)

### Rare public destination queue-builder (feeds a JARM scan pipeline)
No passive MDE-native JARM detection exists — JARM requires active probing — but new/low-volume public HTTPS destinations are a reasonable queue of what to scan next.
```kql
DeviceNetworkEvents
| where RemotePort == 443 and RemoteIPType == "Public"
| where ActionType == "ConnectionSuccess"
| summarize FirstSeen = min(Timestamp), Connections = count() by RemoteIP
| where FirstSeen > ago(24h) and Connections < 10
| sort by FirstSeen desc
```
Source: [03-http-tls/05-jarm-fingerprinting.md](03-http-tls/05-jarm-fingerprinting.md)

---

## Reconnaissance & Lateral Movement

### Port scan detection (high-volume / high-distinct-port)
Flags hosts hitting either a large number of distinct ports or an abnormally high connection-attempt count in a short window — the standard TCP port-scan signature.
```kql
DeviceNetworkEvents
| where Timestamp > ago(10m)
| where ActionType == "ConnectionAttempt"   // TCP SYN sent, handshake not yet complete
| summarize Attempts = count(),
            DistinctPorts = dcount(RemotePort)
  by DeviceName, RemoteIP, bin(Timestamp, 1m)
| where Attempts > 100 or DistinctPorts > 20
| sort by Attempts desc
```
Source: [01-osi-tcp-ip/02-tcp-handshake.md](01-osi-tcp-ip/02-tcp-handshake.md)

### IP-to-MAC instability (ARP spoofing, Zeek sensor)
Detects a single IP address being claimed by more than one MAC address — the core signature of ARP spoofing / cache poisoning.
```kql
Zeek_ARP_CL
| where TimeGenerated > ago(1h)
| summarize MACs = make_set(dst_mac), Changes = count()
  by dst_ip
| where array_length(MACs) > 1   // same IP advertising multiple MACs
| project dst_ip, MACs, Changes
| sort by Changes desc
```
Source: [04-routing-switching/01-arp-basics.md](04-routing-switching/01-arp-basics.md)

### Broadcast-range connection scan (indirect ARP/L2 pivot)
Flags local hosts generating an unusually high count of broadcast-destination connections, which can indicate ARP-based network scanning or discovery tooling.
```kql
Zeek_Conn_CL
| where TimeGenerated > ago(10m)
| where id_resp_h endswith ".255" or id_resp_h == "255.255.255.255"
| summarize BroadcastCount = count() by id_orig_h, bin(TimeGenerated, 1m)
| where BroadcastCount > 50
| sort by BroadcastCount desc
```
Source: [04-routing-switching/01-arp-basics.md](04-routing-switching/01-arp-basics.md)

### Gratuitous ARP / spoofer signature (Zeek sensor)
Flags a MAC address claiming ownership of multiple IPs via unsolicited or mismatched ARP replies — a more targeted spoofing detector than plain IP-to-MAC instability.
```kql
Zeek_ARP_CL
| where TimeGenerated > ago(5m)
| where isGratuitous == true or mac_src != mac_orig   // unsolicited or mismatched reply
| summarize SpoofedIPs = make_set(dst_ip), count()
  by mac_src, src_ip
| where array_length(SpoofedIPs) > 1 or count_ > 30
| sort by count_ desc
```
Source: [04-routing-switching/02-arp-spoofing.md](04-routing-switching/02-arp-spoofing.md)

### Dynamic ARP Inspection violations (switch syslog)
Surfaces DAI violations logged by a managed switch — a high-confidence, low-noise alternative to sensor-based detection when switch syslog is available.
```kql
CommonSecurityLog
| where TimeGenerated > ago(1h)
| where DeviceVendor == "Cisco" and Activity == "SW_DAI"
| where Message has "ARP_Inspect" and Message has "DHCP_SNOOPING_DENY"
| project TimeGenerated, DeviceName, SourceIP, SourceMACAddress, Message
| sort by TimeGenerated desc
```
Source: [04-routing-switching/02-arp-spoofing.md](04-routing-switching/02-arp-spoofing.md)

### Native VLAN mismatch / unexpected trunk negotiation (switch syslog)
Detects VLAN-hopping precursors — native VLAN mismatches and unexpected DTP trunk formation — from Cisco switch syslog forwarded to Sentinel.
```kql
CommonSecurityLog
| where TimeGenerated > ago(1h)
| where DeviceVendor == "Cisco"
| where Message has "Native VLAN mismatch"   // CDP-4-NATIVE_VLAN_MISMATCH — real Cisco log
       or Message has "TRUNKPORTON"           // DTP-5-TRUNKPORTON — unexpected trunk formed
       or Message has "DYNAMICTRUNK"          // DTP negotiated a trunk on an access port
| project TimeGenerated, DeviceName, SourceIP, Message
| sort by TimeGenerated desc
```
Source: [04-routing-switching/03-vlan-hopping.md](04-routing-switching/03-vlan-hopping.md)

### DHCP snooping violations (rogue server / starvation, switch syslog)
Surfaces DHCP snooping violations from switch syslog — an untrusted port answering with Offer/Ack (rogue server) or a client MAC mismatch (common in starvation floods).
```kql
CommonSecurityLog
| where TimeGenerated > ago(1h)
| where DeviceVendor == "Cisco"
| where Message has "DHCP_SNOOPING_UNTRUSTED_PORT"
       or Message has "DHCP_SNOOPING_MATCH_MAC_FAIL"
| project TimeGenerated, DeviceName, SourceIP, SourceMACAddress, Message
| sort by TimeGenerated desc
```
Source: [04-routing-switching/04-rogue-dhcp.md](04-routing-switching/04-rogue-dhcp.md)

### Abnormal DHCP Discover volume from one MAC (starvation, Zeek sensor)
Flags a single MAC address sending far more DHCP Discover messages than any legitimate host would in a short window — the starvation-flood signature that precedes a rogue server taking over lease assignment.
```kql
Zeek_DHCP_CL
| where TimeGenerated > ago(5m)
| where msg_types has "DISCOVER"
| summarize DiscoverCount = count() by mac, bin(TimeGenerated, 1m)
| where DiscoverCount > 100
| sort by DiscoverCount desc
```
Source: [04-routing-switching/04-rogue-dhcp.md](04-routing-switching/04-rogue-dhcp.md)

---

## ICMP & Protocol Abuse

### Oversized ICMP payload (tunnelling, Zeek sensor)
Flags ICMP echo traffic carrying far more data than a standard ping — `icmpsh`/`ptunnel`-style tools abuse the unrestricted payload field of echo request/reply packets to carry C2 or exfil data.
```kql
Zeek_Conn_CL
| where TimeGenerated > ago(24h)
| where proto == "icmp"
| where orig_bytes > 64   // standard ping payload is 32-56 bytes
| project TimeGenerated, id_orig_h, id_resp_h, orig_bytes, resp_bytes, duration
| sort by orig_bytes desc
```
Source: [01-osi-tcp-ip/04-icmp-tunnelling.md](01-osi-tcp-ip/04-icmp-tunnelling.md)

### Sustained ICMP volume between a host pair (tunnelling, Zeek sensor)
Diagnostic pings are sporadic; a tunnel sustains steady traffic. Flags host pairs exchanging a high count of ICMP packets in a short window.
```kql
Zeek_Conn_CL
| where TimeGenerated > ago(1h)
| where proto == "icmp"
| summarize IcmpCount = count(), AvgBytes = avg(orig_bytes)
  by id_orig_h, id_resp_h, bin(TimeGenerated, 5m)
| where IcmpCount > 100
| sort by IcmpCount desc
```
Source: [01-osi-tcp-ip/04-icmp-tunnelling.md](01-osi-tcp-ip/04-icmp-tunnelling.md)

### Custom-size ping command line (MDE process pivot)
MDE has no ICMP packet visibility, but `ping.exe` invoked with a payload size (`-l`) near the 65500-byte maximum is a visible precursor worth flagging.
```kql
DeviceProcessEvents
| where FileName in~ ("ping.exe", "ping")
| where ProcessCommandLine has "-l "
| extend SizeArg = extract(@"-l\s+(\d+)", 1, ProcessCommandLine)
| where isnotempty(SizeArg) and toint(SizeArg) > 1000
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
| sort by Timestamp desc
```
Source: [01-osi-tcp-ip/04-icmp-tunnelling.md](01-osi-tcp-ip/04-icmp-tunnelling.md)

---

## General / Foundational Network Anomalies

### Unusual destination port usage
A broad, layer-4 starting point: flags process-to-port combinations outside common well-known ports, useful as a first-pass triage query before applying more targeted detections above.
```kql
DeviceNetworkEvents
| where RemotePort !in (80, 443, 53, 22, 25, 445)
| summarize count() by RemotePort, InitiatingProcessFileName
| sort by count_ desc
```
Source: [01-osi-tcp-ip/01-osi-model.md](01-osi-tcp-ip/01-osi-model.md)
