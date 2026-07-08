# Masquerading and Unsigned Binaries

- [ ] Read
- [ ] Reviewed KQL example
- [ ] Could explain this to someone else

## Why this matters for detection

A renamed binary still has the same hash and behaviour — masquerading only works on analysts and tools that trust the filename, not on anything that actually checks the file.

## Core concept

- **Masquerading:** naming or placing a malicious binary to look like a trusted one — e.g. renaming `cmd.exe` to `update.exe`. The functionality and hash don't change, only what shows up in a process list, hoping an analyst skims past a familiar-sounding name.
- **Signature/hash mismatch:** MDE natively records each process's hash and signing status. Comparing a well-known filename against its expected hash/signer catches renamed-but-not-fully-disguised binaries instantly — a file named `svchost.exe` that isn't signed by Microsoft, or whose hash doesn't match the real System32 binary, is an immediate red flag.
- **Path-based masquerading:** certain binaries only ever legitimately run from one location. `svchost.exe` from anywhere other than `C:\Windows\System32` (or `SysWOW64`) is virtually always malicious — Windows itself never launches the real one from anywhere else.

## Diagram

```
Legitimate: C:\Windows\System32\svchost.exe   (signed by Microsoft, launched by services.exe)
Masquerade: C:\Users\bob\Downloads\svchost.exe  ← same name, wrong path, wrong/no signature
```

## KQL Example

**Variant A — path-based masquerade of a well-known system binary:**

```kql
DeviceProcessEvents
| where FileName =~ "svchost.exe"
| where FolderPath !has @"\Windows\System32" and FolderPath !has @"\Windows\SysWOW64"
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine
| sort by Timestamp desc
```

**Variant B — signer mismatch for sensitive system binary names:**

```kql
let SensitiveNames = dynamic(["svchost.exe", "lsass.exe", "explorer.exe", "winlogon.exe", "services.exe"]);
DeviceProcessEvents
| where FileName in~ (SensitiveNames)
| join kind=inner (
    DeviceFileCertificateInfo
    | project SHA1, IsTrusted, Signer
  ) on SHA1
| where IsTrusted == false or Signer !has "Microsoft"
| project Timestamp, DeviceName, FileName, FolderPath, Signer, IsTrusted
| sort by Timestamp desc
```
