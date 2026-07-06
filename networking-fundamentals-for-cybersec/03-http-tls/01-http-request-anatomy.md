# HTTP Request Anatomy

- [ ] Read
- [ ] Reviewed KQL example
- [ ] Could explain this to someone else

## Why this matters for detection

Malware C2 and web-based attacks hide in HTTP headers and URIs — reading a raw request tells you exactly what an attacker sent and where to look in your proxy logs.

## Core concept

- **Request line**: `METHOD /path HTTP/1.1`. Methods to watch: GET (data retrieval), POST (data submission — common for exfil and C2 check-ins), PUT/DELETE (REST abuse).
- **Key headers**: `Host` (target domain), `User-Agent` (client identifier — frequently spoofed by malware), `Content-Type`, `Authorization`, `Referer`. Missing or default `User-Agent` strings are a red flag.
- **URL structure**: `scheme://host:port/path?query#fragment`. Encoded characters (`%2e`, `%2f`) in the path are used in path traversal and WAF evasion.

## Diagram

```
POST /c2/checkin HTTP/1.1
Host: updates.legit-looking.com
User-Agent: Mozilla/5.0 (Windows NT 10.0)   ← often hardcoded in implants
Content-Type: application/octet-stream
Content-Length: 256

[base64-encoded beacon payload]
```

## KQL Example

Find uncommon or hardcoded User-Agent strings in proxy logs:

```kql
DeviceNetworkEvents
| where RemotePort in (80, 443, 8080)
| summarize count() by InitiatingProcessFileName, RemoteUrl
| where count_ < 5
| sort by count_ asc
```
