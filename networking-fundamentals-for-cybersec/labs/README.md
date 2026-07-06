# Labs

Hands-on exercises that reinforce the sec-dojo lessons using real packet capture and analysis tools on your homelab/sensor host.

## Prerequisites

- **Zeek** installed and pointed at a network interface or PCAP file
- **Suricata** for signature-based detection exercises
- **tcpdump** / **Wireshark** for packet-level inspection
- PCAP files stored at `~/pcaps/` on your lab VM (or wherever you keep them)

## How labs work

Each lab has:
1. **Objective** — what you're trying to observe or detect
2. **Setup** — how to generate or source the traffic
3. **Task** — what to find, with hints for Zeek/Suricata/KQL
4. **Verify** — how to confirm you got the right answer

---

## Lab 01 — ARP Spoofing Detection with Zeek

**Linked lesson:** [ARP Basics](../04-routing-switching/01-arp-basics.md) · [ARP Spoofing](../04-routing-switching/02-arp-spoofing.md)

### Objective

Capture an ARP spoofing attack in a PCAP and use Zeek to identify the attacking host.

### Setup

On your lab VM, run a controlled ARP spoof between two test VMs (or use a pre-captured PCAP):

```bash
# Option A: generate live traffic with Bettercap (on isolated lab VLAN only)
sudo bettercap -iface eth1 -eval "set arp.spoof.targets 192.168.10.5; arp.spoof on"

# Option B: use a pre-captured PCAP
tcpdump -i eth1 -w ~/pcaps/arp-spoof.pcap arp
```

### Task

Run Zeek against the PCAP and inspect the ARP log:

```bash
zeek -r ~/pcaps/arp-spoof.pcap /opt/zeek/share/zeek/policy/protocols/arp/detect-MiTM.zeek
cat zeek-logs/arp.log | zeek-cut src_ip dst_ip mac_src | sort | uniq -c | sort -rn
```

**Find:** Which source MAC address claimed to own more than one IP address?

### Verify

```bash
# You should see a notice.log entry like:
grep "ARP::Address_Scan\|ARP::Arp_Reply_Wo_Request" zeek-logs/notice.log
```

Expected output: a `Notice::ACTION_LOG` entry with the attacker's MAC and the IPs it claimed.

---

## Lab 02 — JA3 Fingerprinting with Zeek

**Linked lesson:** [JA3 TLS Fingerprinting](../03-http-tls/03-ja3-fingerprinting.md)

### Objective

Capture TLS handshake traffic, extract JA3 hashes with Zeek, and match them against a known-bad list.

### Setup

Generate TLS traffic from a few different clients (browser, curl, Python requests, a C2 implant in a sandbox):

```bash
# Capture TLS traffic from a test session
tcpdump -i eth0 -w ~/pcaps/tls-mix.pcap 'tcp port 443'

# In another terminal, make some connections:
curl https://example.com
python3 -c "import requests; requests.get('https://example.com')"
```

### Task

Run Zeek with the JA3 package and inspect the SSL log:

```bash
# Install JA3 package if not already present
zkg install salesforce/ja3

zeek -r ~/pcaps/tls-mix.pcap policy/protocols/ssl/validate-certs policy/protocols/ssl/log-hostcerts-only ja3
cat zeek-logs/ssl.log | zeek-cut ja3 ja3s server_name id.orig_h | column -t
```

**Find:** How many distinct JA3 hashes appear? Can you identify which hash belongs to which tool?

Cross-reference against the known-bad list from the lesson (Metasploit: `e7d705a3286e19ea42f587b344ee6865`).

### Verify

```bash
# Count unique JA3 hashes
cat zeek-logs/ssl.log | zeek-cut ja3 | sort | uniq -c | sort -rn

# Check for any known-bad matches
grep "e7d705a3286e19ea42f587b344ee6865\|6bea65e94c4b4b67d197a05f60d46f78" zeek-logs/ssl.log
```

---

## Planned labs *(coming soon)*

| Lab | Topic | Tools |
|---|---|---|
| Lab 03 | DNS tunnelling — detect Iodine traffic | Zeek dns.log, entropy analysis |
| Lab 04 | Beacon detection — regular interval identification | Python + Zeek conn.log |
| Lab 05 | VLAN hopping — double-tag detection | Zeek + Wireshark dissection |
| Lab 06 | DGA simulation — generate and detect | Python DGA script + Zeek dns.log |
