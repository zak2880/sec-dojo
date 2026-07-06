# Glossary

Alphabetical one-line definitions for terms used across sec-dojo modules.

---

| Term | Definition |
|---|---|
| **ARP (Address Resolution Protocol)** | L2 protocol that maps IP addresses to MAC addresses within a subnet; completely unauthenticated. |
| **ARP spoofing** | Attack where a host sends forged ARP replies to poison victims' caches and intercept traffic (MITM). |
| **Beaconing** | Periodic outbound connections from a compromised host to a C2 server to check for commands. |
| **C2 (Command and Control)** | Infrastructure used by an attacker to communicate with and task compromised systems. |
| **CNAME** | DNS record type that aliases one domain name to another instead of returning an IP address. |
| **DGA (Domain Generation Algorithm)** | Malware technique that seeds a PRNG to generate many candidate C2 domains, making blocklisting ineffective. |
| **DNS tunnelling** | Exfiltration or C2 technique that encodes data inside DNS query/response fields to evade firewalls. |
| **Dynamic ARP Inspection (DAI)** | Managed-switch feature that validates ARP packets against a DHCP snooping table to block spoofing. |
| **Encapsulation** | Process of wrapping data with protocol headers at each OSI layer during transmission. |
| **Fast-flux** | DNS technique rotating many short-TTL A records rapidly to make C2 infrastructure harder to block. |
| **Gratuitous ARP** | Unsolicited ARP reply a host sends to announce its IP-MAC mapping; abused in ARP spoofing. |
| **JA3** | MD5 fingerprint of five ClientHello fields (TLS version, ciphers, extensions, curves, point formats). |
| **JA3S** | MD5 fingerprint of the TLS ServerHello; paired with JA3 to identify specific client-server pairs. |
| **Jitter** | Random variance added to a beacon's sleep interval to evade time-based detection analytics. |
| **KQL (Kusto Query Language)** | Query language used in Microsoft Sentinel, Log Analytics, and MDE for threat hunting and detection. |
| **MTU (Maximum Transmission Unit)** | Largest packet size a network interface will send without fragmentation (Ethernet default: 1500 bytes). |
| **NXDOMAIN** | DNS response code meaning the queried domain does not exist; storms of these indicate DGA activity. |
| **PRNG (Pseudo-Random Number Generator)** | Deterministic algorithm producing pseudo-random output; used in DGAs to make domain generation reproducible from a shared seed. |
| **SNI (Server Name Indication)** | TLS extension in the ClientHello that tells the server which hostname the client is connecting to; visible in plaintext. |
| **SYN flood** | DoS attack sending many TCP SYN packets without completing handshakes, exhausting server connection tables. |
| **TCP (Transmission Control Protocol)** | Connection-oriented L4 protocol with handshake, ordered delivery, and retransmission. |
| **TTL (Time to Live)** | DNS: how long a record is cached (seconds). IP: hop counter decremented by each router, packet dropped at 0. |
| **UDP (User Datagram Protocol)** | Connectionless L4 protocol with no handshake or delivery guarantee; used by DNS, DHCP, NTP, QUIC. |
| **VLAN hopping** | Attack allowing an endpoint to send/receive traffic on a VLAN it shouldn't have access to (switch spoofing or double-tagging). |
| **Zeek (formerly Bro)** | Open-source network analysis framework that produces structured logs (conn.log, dns.log, ssl.log, etc.) from raw traffic. |
