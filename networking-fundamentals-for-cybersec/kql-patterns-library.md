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
