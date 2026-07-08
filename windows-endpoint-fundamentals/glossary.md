# Glossary

Alphabetical one-line definitions for terms introduced in the windows-endpoint-fundamentals module. Terms already defined in the [networking module glossary](../networking-fundamentals-for-cybersec/glossary.md) (e.g. KQL, C2) aren't repeated here.

---

| Term | Definition |
|---|---|
| **AMSI (Antimalware Scan Interface)** | Windows API that lets scripting engines (PowerShell, VBA, JScript) submit content to the registered AV/EDR for scanning before execution. |
| **ASR (Attack Surface Reduction) rule** | Microsoft Defender policy that blocks or audits specific high-risk behaviors (e.g. LSASS credential theft, process injection); not enabled by default. |
| **Clipper malware** | Malware that monitors the clipboard for wallet/credential patterns and silently substitutes an attacker-controlled value on paste. |
| **CommandLineEventConsumer** | The most abused WMI event consumer type — executes an arbitrary command when its bound filter fires. |
| **CreateRemoteThread** | Windows API used to create a thread inside another process's address space; a classic DLL/code injection primitive. |
| **Credential dumping** | Extracting stored authentication material (hashes, tickets, plaintext passwords) from memory or disk, most commonly from LSASS. |
| **DPAPI (Data Protection API)** | Windows API that encrypts secrets (e.g. saved browser credentials) tied to the logged-on user's context, decrypting trivially while running as that user. |
| **EncodedCommand** | PowerShell's `-EncodedCommand`/`-enc` flag, which runs a Base64-encoded script; commonly used to obscure attacker intent from casual command-line review. |
| **ETW (Event Tracing for Windows)** | OS-wide logging framework that EDR products subscribe to for real-time telemetry. |
| **Infostealer** | Malware category focused on harvesting credentials, session tokens, and other sensitive data for exfiltration/monetization rather than persistence or destruction. |
| **LOLBAS (Living Off The Land Binaries And Scripts)** | Community-maintained project cataloging native Windows binaries with documented abuse techniques. |
| **LOLBin (Living-off-the-Land Binary)** | A legitimate, typically Microsoft-signed Windows binary abused to download or execute attacker content, evading signature-based AV. |
| **LSASS (Local Security Authority Subsystem Service)** | Windows process that holds credential material in memory for logged-on users; the top target for credential dumping. |
| **Masquerading** | Naming or placing a malicious binary to resemble a trusted one (renamed filename, wrong-but-plausible path) without changing its actual behavior. |
| **MFT (Master File Table)** | NTFS structure recording metadata (including timestamps) for every file on a volume; the target of timestomping. |
| **Mimikatz** | Widely known open-source tool for extracting credentials from LSASS memory; its access patterns are a common detection signature even when the tool itself isn't directly observed. |
| **Module Logging (Event ID 4103)** | PowerShell logging feature recording each pipeline execution and parameter values; not enabled by default. |
| **NTLM (NT LAN Manager)** | Legacy Windows authentication protocol that accepts a password hash as proof of knowledge, enabling Pass-the-Hash attacks. |
| **Pass-the-Hash** | Lateral movement technique authenticating with a captured NTLM hash directly, without ever cracking it to plaintext. |
| **PID / PPID** | Process ID and Parent Process ID — the identifiers that link a process to the process that spawned it, forming the process tree. |
| **Process hollowing** | Injection technique that launches a legitimate process suspended, unmaps its real memory image, and writes malicious code in its place before resuming. |
| **Process tree** | The parent-child lineage of running processes; the basis for most process-based endpoint detections. |
| **ProcessAccess** | An event (Sysmon Event ID 10) logging one process opening a handle to another — the signal used to catch LSASS access attempts. |
| **Reflective DLL injection** | DLL injection variant that loads the DLL directly from memory, never writing it to disk. |
| **Script Block Logging (Event ID 4104)** | PowerShell logging feature recording the full text of executed script blocks, including content after deobfuscation; not enabled by default. |
| **Sysmon (System Monitor)** | Sysinternals tool that extends Windows event logging with rich, structured telemetry (process creation, network connections, image loads, registry changes, and more). |
| **Timestomping** | Modifying a file's MFT timestamps to disguise when it was actually created or modified, evading timeline-based forensic review. |
