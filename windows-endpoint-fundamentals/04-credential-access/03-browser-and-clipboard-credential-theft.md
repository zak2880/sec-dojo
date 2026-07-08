# Browser and Clipboard Credential Theft

- [ ] Read
- [ ] Reviewed KQL example
- [ ] Could explain this to someone else

## Why this matters for detection

Infostealers rarely intercept a login form — it's far simpler to steal the credential store the browser already decrypted for you.

## Core concept

- **Browser credential stores** (e.g. Chrome's `Login Data` SQLite file) hold saved credentials encrypted with **DPAPI**, tied to the logged-on user. Because DPAPI decryption succeeds trivially while running *as that same user*, an infostealer doesn't need to break any encryption — it just needs to read the file as the victim.
- **Infostealer families** (RedLine, Raccoon, Vidar-class) target these files directly, along with cookie stores (for session-token theft that bypasses MFA entirely) rather than phishing credentials through a fake login page.
- **Clipboard monitoring malware ("clippers"):** watches the clipboard for patterns matching crypto wallet addresses or credentials, then silently substitutes an attacker-controlled value on paste. No injection or elevation required — just a process polling the clipboard API.
- Both matter specifically for **infostealer detection** because they represent a distinct kill-chain stage — data collection, often the actual monetization goal behind what looked like a "boring" loader infection.

> ⚠️ **Caveat:** Native Windows/MDE telemetry doesn't log clipboard read/write operations directly. Clipboard-based detection relies on **process-behaviour inference** (an unusual process quietly persisting and touching browser/credential paths) rather than a dedicated event.

## Diagram

```
infostealer.exe reads:
  %LocalAppData%\Google\Chrome\User Data\Default\Login Data   (saved credentials)
  %LocalAppData%\Google\Chrome\User Data\Default\Cookies      (session tokens)
                    │
                    ▼
        Immediate outbound connection = collection → exfil, back to back
```

## KQL Example

**Variant A — non-browser process reading browser credential store files:**

```kql
DeviceFileEvents
| where FileName in~ ("Login Data", "Cookies")
| where FolderPath has @"\User Data\"
| where InitiatingProcessFileName !in~ ("chrome.exe", "msedge.exe", "firefox.exe", "brave.exe")
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessFolderPath, FileName, FolderPath
| sort by Timestamp desc
```

**Variant B — credential-store read immediately followed by outbound connection (collection → exfil):**

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
| where ConnTime between (ReadTime .. ReadTime + 2m)   // connection within 2 minutes of the read
| project ReadTime, DeviceName, InitiatingProcessId, RemoteUrl, RemoteIP
| sort by ReadTime desc
```
