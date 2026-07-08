# Pass-the-Hash Basics

- [ ] Read
- [ ] Reviewed KQL example
- [ ] Could explain this to someone else

## Why this matters for detection

Pass-the-Hash means an attacker never needs the plaintext password at all — a captured NTLM hash alone is enough to authenticate as that user against anything that accepts NTLM.

## Core concept

- **NTLM hash reuse:** the NTLM protocol accepts the hash itself as proof of knowledge during authentication — it was never designed to require the plaintext. An attacker holding just the hash (e.g. from an earlier LSASS dump) can authenticate as that user against SMB, WMI, and RDP (in Restricted Admin mode) without ever cracking it.
- **Endpoint-visible symptoms:** the same account authenticating from multiple hosts near-simultaneously (not physically possible for one interactive session), logon type **3** (Network) or **9** (NewCredentials, i.e. `runas /netonly`) immediately preceding lateral-movement tooling, and a spike in **NTLM** authentication where **Kerberos** would normally be expected in an AD environment.
- This lesson only covers what's **visible from the endpoint side** — the account suddenly showing up somewhere it shouldn't, via a logon type that doesn't fit its normal behaviour.

> **Note:** Deeper coverage of Kerberos ticket attacks (Kerberoasting, Golden/Silver Ticket, delegation abuse) and full NTLM relay chains belongs in a future **Identity & Authentication** module — this lesson deliberately stays shallow.

## Diagram

```
Attacker dumps NTLM hash from Host A (via LSASS dump)
          │
          ▼
Attacker authenticates to Host B as the SAME account, hash-only, no crack needed
          │
          ▼
SecurityEvent: 4624, LogonType 3, AuthenticationPackageName = NTLM
```

## KQL Example

**Variant A — same account authenticating from multiple hosts in a short window:**

```kql
SecurityEvent
| where EventID == 4624
| where LogonType in (3, 9)
| summarize DistinctHosts = dcount(Computer), Hosts = make_set(Computer)
  by TargetUserName, bin(TimeGenerated, 15m)
| where DistinctHosts > 3   // one account, many hosts, same short window
| sort by DistinctHosts desc
```

**Variant B — NTLM authentication volume where Kerberos is expected:**

```kql
SecurityEvent
| where EventID == 4624
| where AuthenticationPackageName == "NTLM"
| where LogonType == 3
| summarize NtlmLogons = count(), Accounts = dcount(TargetUserName)
  by Computer, bin(TimeGenerated, 1h)
| where NtlmLogons > 20   // AD-joined servers should mostly see Kerberos, not NTLM, at this volume
| sort by NtlmLogons desc
```
