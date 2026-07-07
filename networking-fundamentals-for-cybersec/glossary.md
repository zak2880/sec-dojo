# Glossary

Alphabetical one-line definitions for terms used across sec-dojo modules.

---

| Term | Definition |
|---|---|
| **ARP (Address Resolution Protocol)** | L2 protocol that maps IP addresses to MAC addresses within a subnet; completely unauthenticated. |
| **ARP spoofing** | Attack where a host sends forged ARP replies to poison victims' caches and intercept traffic (MITM). |
| **Beaconing** | Periodic outbound connections from a compromised host to a C2 server to check for commands. |
| **C2 (Command and Control)** | Infrastructure used by an attacker to communicate with and task compromised systems. |
| **C2 over legitimate services (SaaS-based C2)** | C2 technique routing traffic through trusted platforms (Slack, Discord, Dropbox, GitHub) that can't be blocklisted outright. |
| **CNAME** | DNS record type that aliases one domain name to another instead of returning an IP address. |
| **DGA (Domain Generation Algorithm)** | Malware technique that seeds a PRNG to generate many candidate C2 domains, making blocklisting ineffective. |
| **DHCP snooping** | Managed-switch feature that trusts DHCP server messages only on designated ports, blocking rogue DHCP servers. |
| **DHCP starvation** | Attack flooding a segment with spoofed DHCP Discover requests to exhaust the legitimate address pool. |
| **DNS tunnelling** | Exfiltration or C2 technique that encodes data inside DNS query/response fields to evade firewalls. |
| **DNS-over-HTTPS (DoH)** | DNS resolution wrapped inside an HTTPS request (typically port 443), indistinguishable from other web traffic. |
| **DNS-over-TLS (DoT)** | DNS resolution wrapped inside a TLS session on a dedicated port (853); hides query content but not the port. |
| **Domain fronting** | Technique where the cleartext TLS SNI names a trusted CDN domain while the encrypted HTTP Host header requests a different, attacker-controlled backend. |
| **DORA** | DHCP's four-step lease process: Discover, Offer, Request, Acknowledge. |
| **Double-flux** | Fast-flux variant where the domain's authoritative nameservers, not just its A records, also rotate across bot infrastructure. |
| **Dynamic ARP Inspection (DAI)** | Managed-switch feature that validates ARP packets against a DHCP snooping table to block spoofing. |
| **Encapsulation** | Process of wrapping data with protocol headers at each OSI layer during transmission. |
| **Fast-flux** | DNS technique rotating many short-TTL A records rapidly to make C2 infrastructure harder to block. |
| **Gratuitous ARP** | Unsolicited ARP reply a host sends to announce its IP-MAC mapping; abused in ARP spoofing. |
| **ICMP (Internet Control Message Protocol)** | L3 diagnostic/control protocol (ping, traceroute, unreachable messages) rarely monitored compared to TCP/UDP. |
| **ICMP tunnelling** | C2/exfiltration technique abusing the unrestricted payload field of ICMP echo request/reply packets to carry data. |
| **JA3** | MD5 fingerprint of five ClientHello fields (TLS version, ciphers, extensions, curves, point formats). |
| **JA3S** | MD5 fingerprint of the TLS ServerHello; paired with JA3 to identify specific client-server pairs. |
| **JARM** | Fingerprint of a TLS server's stack configuration, built by hashing its responses to 10 crafted ClientHellos; the server-side counterpart to JA3. |
| **Jitter** | Random variance added to a beacon's sleep interval to evade time-based detection analytics. |
| **KQL (Kusto Query Language)** | Query language used in Microsoft Sentinel, Log Analytics, and MDE for threat hunting and detection. |
| **Malleable C2 profile** | Configurable Cobalt Strike-style template that rewrites beacon HTTP URIs/headers to mimic legitimate services. |
| **MTU (Maximum Transmission Unit)** | Largest packet size a network interface will send without fragmentation (Ethernet default: 1500 bytes). |
| **NXDOMAIN** | DNS response code meaning the queried domain does not exist; storms of these indicate DGA activity. |
| **PRNG (Pseudo-Random Number Generator)** | Deterministic algorithm producing pseudo-random output; used in DGAs to make domain generation reproducible from a shared seed. |
| **Rogue DHCP server** | Unauthorized DHCP server handing out attacker-controlled gateway/DNS settings to enable MITM. |
| **Single-flux** | Fast-flux variant where only a domain's A records rotate rapidly across a pool of bot IPs. |
| **SNI (Server Name Indication)** | TLS extension in the ClientHello that tells the server which hostname the client is connecting to; visible in plaintext. |
| **SYN flood** | DoS attack sending many TCP SYN packets without completing handshakes, exhausting server connection tables. |
| **TCP (Transmission Control Protocol)** | Connection-oriented L4 protocol with handshake, ordered delivery, and retransmission. |
| **TTL (Time to Live)** | DNS: how long a record is cached (seconds). IP: hop counter decremented by each router, packet dropped at 0. |
| **UDP (User Datagram Protocol)** | Connectionless L4 protocol with no handshake or delivery guarantee; used by DNS, DHCP, NTP, QUIC. |
| **VLAN hopping** | Attack allowing an endpoint to send/receive traffic on a VLAN it shouldn't have access to (switch spoofing or double-tagging). |
| **Zeek (formerly Bro)** | Open-source network analysis framework that produces structured logs (conn.log, dns.log, ssl.log, etc.) from raw traffic. |
