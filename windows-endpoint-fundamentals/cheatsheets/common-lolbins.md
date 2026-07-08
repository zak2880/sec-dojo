# Common LOLBins

| Binary | Legitimate use | Common abuse | MITRE ATT&CK ID |
|---|---|---|---|
| `certutil.exe` | Certificate/CA management | `-urlcache`/`-decode` used to download and Base64-decode payloads | [T1105](https://attack.mitre.org/techniques/T1105/) |
| `mshta.exe` | Runs Microsoft HTML Application (.hta) files | Executes HTA/JScript/VBScript directly from a remote URL, bypassing download warnings | [T1218.005](https://attack.mitre.org/techniques/T1218/005/) |
| `rundll32.exe` | Runs exported functions from a DLL | Executes malicious DLLs or script content (e.g. via `advpack.dll`), also dumps LSASS via `comsvcs.dll` | [T1218.011](https://attack.mitre.org/techniques/T1218/011/) |
| `regsvr32.exe` | Registers/unregisters COM DLLs | "Squiblydoo" — registers a remote COM scriptlet, executing code with no file written to disk | [T1218.010](https://attack.mitre.org/techniques/T1218/010/) |
| `bitsadmin.exe` | Manages Background Intelligent Transfer Service jobs | Downloads payloads via BITS, evading process-based network monitoring | [T1197](https://attack.mitre.org/techniques/T1197/) |
| `wmic.exe` | WMI command-line management | Remote process execution (`/node:`), living-off-the-land lateral movement | [T1047](https://attack.mitre.org/techniques/T1047/) |
| `msbuild.exe` | Compiles .NET projects | Executes arbitrary C# embedded in an XML project file — signed, trusted compiler as a code-execution proxy | [T1127.001](https://attack.mitre.org/techniques/T1127/001/) |
| `installutil.exe` | .NET Framework installer utility | Executes code via `[System.ComponentModel.Uninstall]`-marked methods, bypassing normal execution | [T1218.004](https://attack.mitre.org/techniques/T1218/004/) |
| `cscript.exe` / `wscript.exe` | Runs VBScript/JScript files | Executes malicious `.vbs`/`.js` payloads, often as a first-stage dropper | [T1059.005](https://attack.mitre.org/techniques/T1059/005/) |
| `forfiles.exe` | Batch-processes files matching a search | Executes an arbitrary command via `/c`, bypassing some command-line-based application controls | [T1202](https://attack.mitre.org/techniques/T1202/) |
| `regasm.exe` / `regsvcs.exe` | Registers .NET assemblies for COM interop | Executes code via `[ComRegisterFunction]`-marked methods in a malicious assembly | [T1218.009](https://attack.mitre.org/techniques/T1218/009/) |
| `csc.exe` | C# command-line compiler (ships with .NET Framework) | Compiles and runs arbitrary C# source on-host, needing no attacker-supplied compiler | [T1027.004](https://attack.mitre.org/techniques/T1027/004/) |
| `mavinject.exe` | Injects DLLs into running processes for App-V | Direct, signed DLL/process injection primitive — no custom injection code needed | [T1055.001](https://attack.mitre.org/techniques/T1055/001/) |
| `odbcconf.exe` | Configures ODBC drivers | Loads and executes a malicious DLL via a crafted response file (`REGSVR` action) | [T1218.008](https://attack.mitre.org/techniques/T1218/008/) |

> Not exhaustive — the **[LOLBAS project](https://lolbas-project.github.io/)** is the living reference for native Windows binary abuse. See [01-process-fundamentals/03-living-off-the-land-binaries.md](../01-process-fundamentals/03-living-off-the-land-binaries.md).
