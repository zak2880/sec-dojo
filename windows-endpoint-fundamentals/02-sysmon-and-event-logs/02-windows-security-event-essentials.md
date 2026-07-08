# Windows Security Event Essentials

- [ ] Read
- [ ] Reviewed KQL example
- [ ] Could explain this to someone else

## Why this matters for detection

Not every environment runs Sysmon — native Windows Security auditing is what you'll have everywhere, and knowing which Event IDs matter turns a noisy default log into a usable detection source.

## Core concept

- **4624 (logon success) / 4625 (logon failure):** the foundation of authentication monitoring. Both carry a **Logon Type** — the field that tells you *how* the logon happened.
- **Logon types that matter most:** **2** (Interactive — physical console logon), **3** (Network — e.g. SMB access, often used by lateral movement/Pass-the-Hash), **10** (RemoteInteractive — RDP). A service account logging on interactively (type 2/10) is almost always wrong.
- **4688 (process creation):** native Windows' answer to Sysmon Event ID 1, but far thinner — no hashes, and full command-line capture requires the non-default "Include command line in process creation events" audit setting on top of the base audit policy.
- **4672 (special privileges assigned):** fires when a logon session is granted admin-equivalent rights (e.g. `SeDebugPrivilege`). An account gaining this that isn't on your known-admin list is worth immediate review.

## Diagram

```
4624/4625  → Logon success/failure  (WHO, and via Logon Type: HOW)
4688       → Process creation        (native, thinner than Sysmon EID 1)
4672       → Special privileges      (admin-equivalent rights granted)
```

## KQL Example

**Variant A — password spray via 4625 (many accounts, one source, short window):**

```kql
SecurityEvent
| where EventID == 4625
| summarize FailedAccounts = dcount(TargetUserName), Attempts = count()
  by IpAddress, bin(TimeGenerated, 10m)
| where FailedAccounts > 10   // many distinct accounts, not just many retries on one
| sort by FailedAccounts desc
```

**Variant B — 4672 special privileges assigned outside a known-admin baseline:**

```kql
let KnownAdmins = datatable(Account: string)[
    "CONTOSO\\svc-backup", "CONTOSO\\it-admin1", "CONTOSO\\it-admin2"
];
SecurityEvent
| where EventID == 4672
| where SubjectUserName !in (KnownAdmins)
| where PrivilegeList has_any ("SeDebugPrivilege", "SeTcbPrivilege", "SeImpersonatePrivilege")
| project TimeGenerated, Computer, SubjectUserName, PrivilegeList
| sort by TimeGenerated desc
```
