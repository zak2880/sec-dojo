# KQL Patterns Library

A single quick-reference of every KQL query taught across the sec-dojo windows-endpoint-fundamentals lessons, organized by detection technique rather than by lesson. Each entry links back to the lesson that explains the underlying theory.

Every query targets native Microsoft Defender XDR tables (`DeviceProcessEvents`, `DeviceRegistryEvents`, `DeviceEvents`, `DeviceFileEvents`, `DeviceImageLoadEvents`, `DeviceNetworkEvents`, `DeviceFileCertificateInfo`) or native Windows event tables (`SecurityEvent`, `Event`) — no sensor caveats apply here. Where a query depends on a non-default audit policy or ASR rule, that's called out per entry (and in the source lesson).

---

## Process Anomalies

### Office apps spawning a shell (baseline)
Flags the classic macro/exploit execution pattern — Office apps spawning `cmd.exe`, `powershell.exe`, or similar.
```kql
DeviceProcessEvents
| where InitiatingProcessFileName in~ ("winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe")
| where FileName in~ ("cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine
| sort by Timestamp desc
```
Source: [01-process-fundamentals/01-process-basics-and-trees.md](01-process-fundamentals/01-process-basics-and-trees.md)

### Unexpected shell parents (tuned)
Widens the parent list beyond Office apps and excludes known-benign automation to cut noise.
```kql
DeviceProcessEvents
| where FileName in~ ("cmd.exe", "powershell.exe", "pwsh.exe")
| where InitiatingProcessFileName in~ ("winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "services.exe", "svchost.exe")
| where InitiatingProcessFolderPath !has @"\Program Files\"
| where AccountName !endswith "$"
| summarize FirstSeen = min(Timestamp), Count = count()
  by DeviceName, AccountName, InitiatingProcessFileName, FileName
| sort by FirstSeen desc
```
Source: [01-process-fundamentals/01-process-basics-and-trees.md](01-process-fundamentals/01-process-basics-and-trees.md)

### Process injection via ASR (requires ASR rule)
Native detection of process injection, gated behind the "Block process injection" ASR rule.
```kql
DeviceEvents
| where ActionType in ("AsrProcessInjectionAudited", "AsrProcessInjectionBlocked")
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, ActionType, FileName
| sort by Timestamp desc
```
Source: [01-process-fundamentals/02-process-injection-basics.md](01-process-fundamentals/02-process-injection-basics.md)

### Unusual DLL load into a sensitive process (no ASR dependency)
Fallback injection signal — an unsigned/uncommon DLL loading into LSASS, svchost, explorer, or winlogon from an unexpected folder.
```kql
DeviceImageLoadEvents
| where InitiatingProcessFileName in~ ("lsass.exe", "svchost.exe", "explorer.exe", "winlogon.exe")
| where FolderPath !startswith @"C:\Windows\System32" and FolderPath !startswith @"C:\Windows\SysWOW64"
| project Timestamp, DeviceName, InitiatingProcessFileName, FileName, FolderPath, SHA256
| sort by Timestamp desc
```
Source: [01-process-fundamentals/02-process-injection-basics.md](01-process-fundamentals/02-process-injection-basics.md)

### LOLBin command-line pattern match (broad)
Flags known LOLBin abuse patterns in `certutil`, `mshta`, `rundll32`, and `regsvr32` command lines.
```kql
DeviceProcessEvents
| where FileName in~ ("certutil.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe")
| where ProcessCommandLine has_any ("urlcache", "http://", "https://", "scrobj.dll", "-decode")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| sort by Timestamp desc
```
Source: [01-process-fundamentals/03-living-off-the-land-binaries.md](01-process-fundamentals/03-living-off-the-land-binaries.md)

### LOLBin usage confirmed by network egress (tuned)
Joins the command-line match against actual observed network activity from the same process, cutting noise from scripts that merely reference a URL without connecting.
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
Source: [01-process-fundamentals/03-living-off-the-land-binaries.md](01-process-fundamentals/03-living-off-the-land-binaries.md)

### Sysmon Event ID 1 — process creation from a Temp-like path (requires Sysmon)
Flags process creation from user-writable, non-standard paths commonly used for staged payloads.
```kql
Event
| where Source == "Microsoft-Windows-Sysmon"
| where EventID == 1
| extend EventData = parse_xml(EventData)
| extend Image = tostring(EventData.DataItem.EventData.Data[4].["#text"])
| where Image has_any (@"\AppData\Local\Temp", @"\Windows\Temp", @"\ProgramData")
| project TimeGenerated, Computer, Image
| sort by TimeGenerated desc
```
Source: [02-sysmon-and-event-logs/01-sysmon-event-ids-overview.md](02-sysmon-and-event-logs/01-sysmon-event-ids-overview.md)

### Path-based masquerade of a well-known system binary
Flags `svchost.exe` running from anywhere other than System32/SysWOW64.
```kql
DeviceProcessEvents
| where FileName =~ "svchost.exe"
| where FolderPath !has @"\Windows\System32" and FolderPath !has @"\Windows\SysWOW64"
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine
| sort by Timestamp desc
```
Source: [05-defense-evasion/02-masquerading-and-unsigned-binaries.md](05-defense-evasion/02-masquerading-and-unsigned-binaries.md)

### Signer mismatch for sensitive system binary names (tuned)
Joins process events against certificate info to catch renamed binaries that also fail signature validation.
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
Source: [05-defense-evasion/02-masquerading-and-unsigned-binaries.md](05-defense-evasion/02-masquerading-and-unsigned-binaries.md)

---

## Logon & Account Activity

### Password spray via failed logons (4625)
Flags a source IP failing logon against many distinct accounts in a short window — spray, not simple brute force.
```kql
SecurityEvent
| where EventID == 4625
| summarize FailedAccounts = dcount(TargetUserName), Attempts = count()
  by IpAddress, bin(TimeGenerated, 10m)
| where FailedAccounts > 10
| sort by FailedAccounts desc
```
Source: [02-sysmon-and-event-logs/02-windows-security-event-essentials.md](02-sysmon-and-event-logs/02-windows-security-event-essentials.md)

### Special privileges assigned outside a known-admin baseline (4672, tuned)
Flags admin-equivalent rights granted to an account not on a maintained allowlist.
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
Source: [02-sysmon-and-event-logs/02-windows-security-event-essentials.md](02-sysmon-and-event-logs/02-windows-security-event-essentials.md)

### Same account authenticating from multiple hosts (Pass-the-Hash symptom)
Flags one account logging on to several distinct hosts within a short window — not physically possible for a single interactive session.
```kql
SecurityEvent
| where EventID == 4624
| where LogonType in (3, 9)
| summarize DistinctHosts = dcount(Computer), Hosts = make_set(Computer)
  by TargetUserName, bin(TimeGenerated, 15m)
| where DistinctHosts > 3
| sort by DistinctHosts desc
```
Source: [04-credential-access/02-pass-the-hash-basics.md](04-credential-access/02-pass-the-hash-basics.md)

### NTLM authentication volume where Kerberos is expected (tuned)
Flags a spike in NTLM logons to AD-joined servers, where Kerberos should dominate.
```kql
SecurityEvent
| where EventID == 4624
| where AuthenticationPackageName == "NTLM"
| where LogonType == 3
| summarize NtlmLogons = count(), Accounts = dcount(TargetUserName)
  by Computer, bin(TimeGenerated, 1h)
| where NtlmLogons > 20
| sort by NtlmLogons desc
```
Source: [04-credential-access/02-pass-the-hash-basics.md](04-credential-access/02-pass-the-hash-basics.md)

---

## PowerShell & Scripting Abuse

### Encoded command via native process events (baseline, no logging config needed)
Catches `-EncodedCommand` usage from default command-line capture — works without PowerShell logging enabled.
```kql
DeviceProcessEvents
| where FileName in~ ("powershell.exe", "pwsh.exe")
| where ProcessCommandLine has_any ("-enc", "-EncodedCommand", "-e ", "FromBase64String")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
| sort by Timestamp desc
```
Source: [02-sysmon-and-event-logs/03-powershell-logging.md](02-sysmon-and-event-logs/03-powershell-logging.md)

### Obfuscation patterns in script block content (4104, requires Script Block Logging)
Catches obfuscation techniques (concatenation, `IEX`, `[char]` tricks) beyond just `-EncodedCommand`.
```kql
Event
| where Source == "Microsoft-Windows-PowerShell"
| where EventID == 4104
| extend EventData = parse_xml(EventData)
| extend ScriptBlockText = tostring(EventData.DataItem.EventData.Data[2].["#text"])
| where ScriptBlockText has_any ("FromBase64String", "IEX", "Invoke-Expression", "-join", "[char]")
| project TimeGenerated, Computer, ScriptBlockText
| sort by TimeGenerated desc
```
Source: [02-sysmon-and-event-logs/03-powershell-logging.md](02-sysmon-and-event-logs/03-powershell-logging.md)

### Native AMSI detection signal (the win case)
Surfaces content AMSI actually caught and reported — relies on AMSI not having been successfully bypassed.
```kql
DeviceEvents
| where ActionType == "AmsiTriggered"
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName
| sort by Timestamp desc
```
Source: [05-defense-evasion/01-amsi-and-etw-bypass-concepts.md](05-defense-evasion/01-amsi-and-etw-bypass-concepts.md)

### AMSI/ETW bypass lexical indicators (catches attempts even if the bypass succeeded)
Flags the bypass code pattern itself in the command line — useful because a successful bypass produces no `AmsiTriggered` event at all.
```kql
DeviceProcessEvents
| where FileName in~ ("powershell.exe", "pwsh.exe")
| where ProcessCommandLine has_any (
    "amsiutils", "amsiInitFailed", "AmsiScanBuffer",
    "EtwEventWrite", "VirtualProtect"
  )
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
| sort by Timestamp desc
```
Source: [05-defense-evasion/01-amsi-and-etw-bypass-concepts.md](05-defense-evasion/01-amsi-and-etw-bypass-concepts.md)

---

## Persistence

### Run/RunOnce key writes pointing at an unusual location
Flags registry persistence values pointing at user-writable paths (AppData, Temp, ProgramData).
```kql
DeviceRegistryEvents
| where ActionType == "RegistryValueSet"
| where RegistryKey has_any (@"\CurrentVersion\Run", @"\CurrentVersion\RunOnce")
| where RegistryValueData has_any (@"\AppData\", @"\Temp\", @"\ProgramData\")
| project Timestamp, DeviceName, InitiatingProcessAccountName, RegistryKey, RegistryValueName, RegistryValueData
| sort by Timestamp desc
```
Source: [03-persistence-mechanisms/01-registry-run-keys-and-startup.md](03-persistence-mechanisms/01-registry-run-keys-and-startup.md)

### New file dropped in the Startup folder
Catches the non-registry equivalent of Run-key persistence.
```kql
DeviceFileEvents
| where ActionType == "FileCreated"
| where FolderPath has @"\Start Menu\Programs\Startup"
| project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, FolderPath, SHA256
| sort by Timestamp desc
```
Source: [03-persistence-mechanisms/01-registry-run-keys-and-startup.md](03-persistence-mechanisms/01-registry-run-keys-and-startup.md)

### Scheduled task created with a suspicious action
Flags new scheduled tasks whose action invokes a shell/LOLBin or points at a user-writable path.
```kql
DeviceEvents
| where ActionType == "ScheduledTaskCreated"
| extend TaskAction = tostring(parse_json(AdditionalFields).ActionCommand)
| where TaskAction has_any ("powershell", "cmd.exe", "mshta", "rundll32", "certutil")
       or TaskAction has_any (@"\Temp\", @"\AppData\")
| project Timestamp, DeviceName, InitiatingProcessAccountName, TaskAction
| sort by Timestamp desc
```
Source: [03-persistence-mechanisms/02-scheduled-tasks-and-services.md](03-persistence-mechanisms/02-scheduled-tasks-and-services.md)

### New service installed from an unusual path
Flags service creation (Event ID 7045 equivalent) where the ImagePath points outside standard install locations.
```kql
DeviceEvents
| where ActionType == "ServiceInstalled"
| extend ServiceImagePath = tostring(parse_json(AdditionalFields).ServiceImagePath)
| where ServiceImagePath has_any (@"\Temp\", @"\AppData\", @"\ProgramData\", @"\Users\Public\")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ServiceImagePath
| sort by Timestamp desc
```
Source: [03-persistence-mechanisms/02-scheduled-tasks-and-services.md](03-persistence-mechanisms/02-scheduled-tasks-and-services.md)

### WMI filter-to-consumer binding created (broad)
Surfaces every new WMI event subscription binding — the stealthiest common persistence mechanism.
```kql
DeviceEvents
| where ActionType == "WmiBindEventFilterToConsumer"
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, AdditionalFields
| sort by Timestamp desc
```
Source: [03-persistence-mechanisms/03-wmi-persistence.md](03-persistence-mechanisms/03-wmi-persistence.md)

### WMI persistence via CommandLineEventConsumer (tuned)
Narrows to the specific WMI consumer type that directly executes a command, cutting noise from monitoring/management tooling using less dangerous consumer types.
```kql
DeviceEvents
| where ActionType in ("WmiCreateEventConsumer", "WmiBindEventFilterToConsumer")
| where AdditionalFields has "CommandLineEventConsumer"
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, AdditionalFields
| sort by Timestamp desc
```
Source: [03-persistence-mechanisms/03-wmi-persistence.md](03-persistence-mechanisms/03-wmi-persistence.md)

---

## Credential Access

### LSASS credential theft via ASR (requires ASR rule)
Native detection of LSASS access consistent with credential dumping, gated behind the "Block credential stealing from LSASS" ASR rule.
```kql
DeviceEvents
| where ActionType in ("AsrLsassCredentialTheftAudited", "AsrLsassCredentialTheftBlocked")
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessAccountName
| sort by Timestamp desc
```
Source: [04-credential-access/01-lsass-and-credential-dumping.md](04-credential-access/01-lsass-and-credential-dumping.md)

### comsvcs.dll MiniDump LSASS dump technique (no ASR dependency)
Catches the signed-DLL LOLBin alternative to running Mimikatz directly — works out of the box.
```kql
DeviceProcessEvents
| where FileName =~ "rundll32.exe"
| where ProcessCommandLine has "comsvcs.dll" and ProcessCommandLine has "MiniDump"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
| sort by Timestamp desc
```
Source: [04-credential-access/01-lsass-and-credential-dumping.md](04-credential-access/01-lsass-and-credential-dumping.md)

### Non-browser process reading browser credential store files
Flags an unexpected process reading Chrome/Edge/Firefox `Login Data` or `Cookies` files — the direct infostealer signature.
```kql
DeviceFileEvents
| where FileName in~ ("Login Data", "Cookies")
| where FolderPath has @"\User Data\"
| where InitiatingProcessFileName !in~ ("chrome.exe", "msedge.exe", "firefox.exe", "brave.exe")
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessFolderPath, FileName, FolderPath
| sort by Timestamp desc
```
Source: [04-credential-access/03-browser-and-clipboard-credential-theft.md](04-credential-access/03-browser-and-clipboard-credential-theft.md)

### Credential-store read immediately followed by outbound connection (collection → exfil, tuned)
Joins the credential-store read against network activity from the same process moments later — the collection-then-exfil pattern typical of infostealers.
```kql
DeviceFileEvents
| where FileName in~ ("Login Data", "Cookies")
| where InitiatingProcessFileName !in~ ("chrome.exe", "msedge.exe", "firefox.exe", "brave.exe")
| project ReadTime = Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessId
| join kind=inner (
    DeviceNetworkEvents
    | where RemoteIPType == "Public"
    | project ConnTime = Timestamp, DeviceName, InitiatingProcessId, RemoteUrl, RemoteIP
  ) on DeviceName, InitiatingProcessId
| where ConnTime between (ReadTime .. ReadTime + 2m)
| project ReadTime, DeviceName, InitiatingProcessId, RemoteUrl, RemoteIP
| sort by ReadTime desc
```
Source: [04-credential-access/03-browser-and-clipboard-credential-theft.md](04-credential-access/03-browser-and-clipboard-credential-theft.md)

---

## Defense Evasion

### Security log cleared (Event ID 1102)
High-fidelity anti-forensics signal — near-zero legitimate reason for a manual audit log clear.
```kql
SecurityEvent
| where EventID == 1102
| project TimeGenerated, Computer, SubjectUserName, Activity
| sort by TimeGenerated desc
```
Source: [05-defense-evasion/03-timestomping-and-log-clearing.md](05-defense-evasion/03-timestomping-and-log-clearing.md)

### System log cleared (Event ID 104)
The System/Application log equivalent of 1102 — retention rollover doesn't produce this, only a manual clear does.
```kql
Event
| where Source == "Microsoft-Windows-Eventlog"
| where EventID == 104
| project TimeGenerated, Computer, UserName, EventID
| sort by TimeGenerated desc
```
Source: [05-defense-evasion/03-timestomping-and-log-clearing.md](05-defense-evasion/03-timestomping-and-log-clearing.md)
