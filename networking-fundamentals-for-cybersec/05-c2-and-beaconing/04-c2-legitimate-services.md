# C2 over Legitimate Services (SaaS-based C2)

- [ ] Read
- [ ] Reviewed KQL example
- [ ] Could explain this to someone else

## Why this matters for detection

Modern C2 frameworks route traffic through Slack, Discord, Dropbox, GitHub, and Office365 precisely because your org can't blanket-block business-critical SaaS platforms — domain/IP blocklisting stops working entirely.

## Core concept

- C2 tooling (e.g. Discord-based C2, Slack-webhook C2, GitHub-gist dead-drops, Dropbox/OneDrive for staging and exfil) uses the platform's own API as the C2 channel — commands and results move through the same endpoints legitimate apps use.
- Because these domains are business-critical, they sit on nearly every organization's allowlist, and the TLS session to them looks identical to normal employee/app traffic — reputation-based blocking has nothing to flag.
- This forces detection to shift from **"where is it going"** (domain/IP reputation) to **"what is going there"** (behavioral/process baselining) — the same SaaS destination is fine from the approved app, suspicious from anything else.
- Detection approach: baseline which processes normally talk to a given SaaS domain (browser, official desktop app, approved integration), then flag connections to it from anything outside that baseline.

## Diagram

```
Normal:   chrome.exe / Slack.exe  → slack.com   (expected, allowlisted)
C2:       powershell.exe          → slack.com   (same trusted domain, hidden in plain sight)
                                     ↑ webhook/API abused as the C2 channel
```

## KQL Example

**Variant A — baseline: non-approved process talking to a SaaS API:**

```kql
DeviceNetworkEvents
| where RemoteUrl has_any ("slack.com", "discord.com", "discordapp.com", "api.dropboxapi.com", "github.com")
| where InitiatingProcessFileName !in~ ("chrome.exe", "msedge.exe", "firefox.exe", "Slack.exe", "Discord.exe", "OneDrive.exe")
| summarize count(), FirstSeen = min(Timestamp) by DeviceName, InitiatingProcessFileName, RemoteUrl
| sort by FirstSeen desc
```

**Variant B — tuned: exclude fleet-wide sanctioned automation:**

Variant A alone also flags legitimate CI bots and integrations that aren't the browser/app. Those typically run from many hosts or a known service account, whereas a real implant's SaaS channel is limited to the handful of hosts it compromised:

```kql
DeviceNetworkEvents
| where RemoteUrl has_any ("slack.com", "discord.com", "discordapp.com", "api.dropboxapi.com", "github.com")
| where InitiatingProcessFileName !in~ ("chrome.exe", "msedge.exe", "firefox.exe", "Slack.exe", "Discord.exe", "OneDrive.exe")
| summarize Hosts = dcount(DeviceName), Connections = count() by InitiatingProcessFileName, RemoteUrl
| where Hosts <= 2   // sanctioned automation usually runs fleet-wide or from a known service account, not 1-2 endpoints
| sort by Connections desc
```
