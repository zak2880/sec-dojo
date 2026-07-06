# Common Ports Cheatsheet

| Port | Protocol | Service | Why it matters for detection |
|------|----------|---------|-------------------------------|
| 20/21 | TCP | FTP (data/control) | Cleartext file transfer; exfiltration channel. Rarely legitimate on modern endpoints. |
| 22 | TCP | SSH | Encrypted remote access. Unusual source IPs or non-admin processes initiating SSH are suspicious. |
| 23 | TCP | Telnet | Cleartext. If seen, likely IoT/OT or misconfiguration. Capture the session. |
| 25 | TCP | SMTP | Outbound mail. Endpoints should not initiate SMTP directly — flag and investigate. |
| 53 | UDP/TCP | DNS | Nearly universal. High-entropy subdomains, large UDP payloads, or TXT queries from workstations = tunnelling risk. |
| 67/68 | UDP | DHCP | Rogue DHCP server attacks redirect traffic. Unexpected DHCP offers on non-server IPs are a red flag. |
| 80 | TCP | HTTP | Cleartext web. C2 frameworks frequently use HTTP to blend with normal traffic. |
| 110 | TCP | POP3 | Legacy cleartext email retrieval. Should not appear from endpoints in modern environments. |
| 123 | UDP | NTP | Time sync. Abused for amplification DDoS; unexpected high-volume NTP from endpoints = flag. |
| 135 | TCP | MS-RPC | Windows RPC endpoint mapper. Exploited in lateral movement (e.g. PsExec, DCOM). |
| 137-139 | UDP/TCP | NetBIOS | Legacy Windows name resolution. Poisoning attacks (Responder) use this. Monitor for LLMNR/NBT-NS. |
| 443 | TCP | HTTPS/TLS | Encrypted web. Most C2 uses 443. JA3 fingerprinting and anomalous process-to-destination combos are key. |
| 445 | TCP | SMB | Windows file sharing. Primary lateral movement vector (EternalBlue, PsExec, ransomware). Alert on unusual source IPs. |
| 514 | UDP | Syslog | Log forwarding. Attacker may redirect to their own collector to suppress evidence. |
| 587 | TCP | SMTP (submission) | Authenticated email submission. Compromised accounts send phishing/spam here. |
| 636 | TCP | LDAPS | Encrypted LDAP. Watch for reconnaissance queries (BloodHound-style enumeration). |
| 1433 | TCP | MSSQL | SQL Server. Direct internet exposure = critical risk. Internal: flag non-DBA processes querying it. |
| 3306 | TCP | MySQL/MariaDB | Same as MSSQL — direct internet access is a critical finding. |
| 3389 | TCP | RDP | Remote Desktop. High-value target for brute force and lateral movement. Restrict to jump hosts. |
| 4444 | TCP | Metasploit default | Non-standard port heavily associated with Metasploit reverse shells. Alert immediately. |
| 5985/5986 | TCP | WinRM (HTTP/S) | PowerShell remoting. Lateral movement via Invoke-Command. Monitor source/dest pairs. |
| 6667 | TCP | IRC | Rarely legitimate on corporate networks. Older botnets and some C2 use IRC. |
| 8080/8443 | TCP | HTTP/S alt | Common C2 alternative ports to blend with dev/proxy traffic. Check against process context. |
| 9001/9030 | TCP | Tor (ORPort/DirPort) | Tor relay defaults. Connections to known Tor guard nodes = high-confidence exfil attempt. |
