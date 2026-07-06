# Protocol Abuse Matrix

| Legitimate Protocol | Common Malicious Abuse | MITRE ATT&CK ID |
|---|---|---|
| DNS (UDP/53) | C2 beaconing, data exfiltration via subdomain encoding, DGA for C2 resilience | [T1071.004](https://attack.mitre.org/techniques/T1071/004/) |
| HTTPS (TCP/443) | C2 over encrypted web (Cobalt Strike, Sliver, Havoc), domain fronting | [T1071.001](https://attack.mitre.org/techniques/T1071/001/) |
| HTTP (TCP/80) | Cleartext C2 channels, malware distribution, staged payload delivery | [T1071.001](https://attack.mitre.org/techniques/T1071/001/) |
| ICMP | Covert channel (data in Echo payload), network reconnaissance, ICMP tunnelling (ptunnel) | [T1095](https://attack.mitre.org/techniques/T1095/) |
| SMB (TCP/445) | Lateral movement (PsExec), ransomware propagation, credential relay (NTLM), EternalBlue exploitation | [T1021.002](https://attack.mitre.org/techniques/T1021/002/) |
| WinRM / PSRemoting (TCP/5985-5986) | Lateral movement via Invoke-Command, living-off-the-land remote execution | [T1021.006](https://attack.mitre.org/techniques/T1021/006/) |
| RDP (TCP/3389) | Lateral movement, persistence via RDP backdoors, session hijacking | [T1021.001](https://attack.mitre.org/techniques/T1021/001/) |
| SSH (TCP/22) | Reverse tunnels to expose internal services externally (SSH -R), credential theft | [T1572](https://attack.mitre.org/techniques/T1572/) |
| NTP (UDP/123) | DDoS amplification (NTP monlist), time manipulation to confuse log correlation | [T1499.002](https://attack.mitre.org/techniques/T1499/002/) |
| ARP (L2, no port) | ARP spoofing/poisoning for MITM, credential capture on LAN | [T1557.002](https://attack.mitre.org/techniques/T1557/002/) |
| LLMNR / NBT-NS (UDP/5355, 137) | Poisoning responses with Responder to capture Net-NTLMv2 hashes | [T1557.001](https://attack.mitre.org/techniques/T1557/001/) |
| SMTP (TCP/25) | Phishing distribution, spam relay from compromised accounts/servers | [T1566.001](https://attack.mitre.org/techniques/T1566/001/) |
| FTP (TCP/21) | Exfiltration of bulk data, malware staging on compromised FTP servers | [T1048.003](https://attack.mitre.org/techniques/T1048/003/) |
| TLS/SNI | Domain fronting (SNI mismatch with Host header to hide true C2 destination) | [T1090.004](https://attack.mitre.org/techniques/T1090/004/) |
| BGP (TCP/179) | BGP hijacking to reroute traffic through adversary-controlled AS (nation-state / ISP level) | [T1557](https://attack.mitre.org/techniques/T1557/) |
| QUIC (UDP/443) | Evading HTTP inspection proxies; some C2 frameworks experimenting with QUIC transport | [T1071.001](https://attack.mitre.org/techniques/T1071/001/) |
| LDAP (TCP/389) | AD enumeration (BloodHound, ldapdomaindump), LDAP injection in web apps | [T1087.002](https://attack.mitre.org/techniques/T1087/002/) |
| Kerberos (TCP/UDP/88) | Kerberoasting (SPN ticket requests), AS-REP Roasting, Pass-the-Ticket | [T1558.003](https://attack.mitre.org/techniques/T1558/003/) |
