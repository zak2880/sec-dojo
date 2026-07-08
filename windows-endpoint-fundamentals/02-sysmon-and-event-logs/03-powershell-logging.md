# PowerShell Logging

- [ ] Read
- [ ] Reviewed KQL example
- [ ] Could explain this to someone else

## Why this matters for detection

PowerShell is the most common post-exploitation shell on Windows precisely because it's already there — logging its content, not just the fact it ran, is what makes it detectable.

## Core concept

- **4103 (Module Logging):** logs each pipeline execution, including parameter values, as PowerShell modules are invoked. Gives visibility into *what* ran through the pipeline.
- **4104 (Script Block Logging):** logs the full text of a script block as it executes — critically, this includes content **after PowerShell's own deobfuscation**, so even heavily obfuscated attacker scripts get logged in their working form.
- **Why obfuscation itself is a red flag:** `-EncodedCommand` (`-enc`/`-e`, a Base64-encoded script), excessive string concatenation (`'p'+'o'+'w'`), and backtick/`[char]`-based tricks exist to *hide intent from a human reading the command line*. Legitimate admin scripts almost never need to obscure their own syntax — so the obfuscation pattern itself is worth flagging even before decoding the payload.

> ⚠️ **Caveat:** 4103/4104 require **Module Logging** and **Script Block Logging** to be enabled via Group Policy or registry — neither is on by default, unlike basic command-line capture in `DeviceProcessEvents`.

## Diagram

```
powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA...
                     └── decodes to a working script block ──┐
                                                              ▼
                                            4104 logs the deobfuscated content
                                            (if Script Block Logging is enabled)
```

## KQL Example

**Variant A — encoded command via native DeviceProcessEvents (no extra config needed):**

MDE captures the full command line by default, so this works even without PowerShell logging enabled:

```kql
DeviceProcessEvents
| where FileName in~ ("powershell.exe", "pwsh.exe")
| where ProcessCommandLine has_any ("-enc", "-EncodedCommand", "-e ", "FromBase64String")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
| sort by Timestamp desc
```

**Variant B — obfuscation patterns in 4104 script block content (requires Script Block Logging):**

Catches obfuscation techniques that don't rely on `-EncodedCommand` at all, e.g. concatenation-based string building:

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
