### General Notes

These are the common commands executed by attackers to perform *Discovery* once they have maintained initial access to a host.
- This is the [[MITRE ATT&CK]]'s tactic, [Discovery](https://attack.mitre.org/tactics/TA0007/).
- All of the commands below are native to Windows, so they blend in with normal admin activity (*Living off the Land*).

> Some of these are present in [[Domain Reconnaissance]]. Without the `/domain` switch, the commands here query the **local** machine, not the [[Domain Controller]].

---
### Files and Folders

Attackers browse files and folders to find out the host's purpose, the victim's job, or their interests.
- Maps to [T1083 - File and Directory Discovery](https://attack.mitre.org/techniques/T1083/).
- Common targets are the user's *Desktop*, *Documents*, and *Downloads* folders, as well as config files and scripts that may hold credentials.

##### `type` / `Get-Content`

```cmd
type C:\Users\<user>\Desktop\notes.txt
```
- `type` is a `cmd.exe` built-in that prints the contents of a file to standard output.
- It is not a standalone executable, so it only shows up in logs as part of the `cmd.exe` command line.

```powershell
Get-Content C:\Users\<user>\Desktop\notes.txt
```
- `Get-Content` reads a file through the PowerShell *FileSystem provider* and returns it line by line as string objects.
- It has the aliases `gc`, `cat`, and `type`, so `type` in PowerShell is actually this cmdlet.
- `-Tail <N>` reads only the last N lines, and `-Raw` returns the whole file as one string.

##### `dir` / `Get-ChildItem`

```cmd
dir /s /a C:\Users\<user>
```
- `dir` is a `cmd.exe` built-in that lists the contents of a folder.
- `/s` recurses into subfolders, and `/a` includes hidden and system files.

```powershell
Get-ChildItem -Path C:\Users\<user> -Recurse -Force -Include *.txt,*.docx,*.kdbx
```
- `Get-ChildItem` enumerates the items of a provider path. For the FileSystem provider these are files and folders.
- `-Recurse` walks subfolders, `-Force` includes hidden items, and `-Include` filters for interesting extensions.
- It has the aliases `gci`, `ls`, and `dir`.

> Attackers often search for keywords like *password*, *vpn*, or *backup* across file names and contents. A recursive search over a user profile right after initial access is a strong signal.

---
### Users and Groups

Attackers enumerate users and groups to find out who uses the host and with which privileges.
- Maps to [T1033 - System Owner/User Discovery](https://attack.mitre.org/techniques/T1033/), [T1087.001 - Local Account](https://attack.mitre.org/techniques/T1087/001/), and [T1069.001 - Local Groups](https://attack.mitre.org/techniques/T1069/001/).

##### `whoami`

```cmd
whoami /all
```
- Displays the security context of the current user: username, *SID*, group memberships, and privileges.
- It reads the *access token* of the current process, so it shows exactly what the attacker's session can do.
- `/priv` shows only the privileges. Attackers look for `SeImpersonatePrivilege` or `SeDebugPrivilege`, which open privilege escalation paths.

##### `net user`

```cmd
net user
net user <username>
```
- Without arguments, lists all local accounts. With a username, shows that account's details: last logon, password last set, and group memberships.
- It queries the local *SAM* database through the Windows *NetAPI* (`NetUserEnum`).
- Adding `/domain` sends the same query to the [[Domain Controller]] instead.

> `net.exe` spawns `net1.exe` to do the actual work, so both show up in process creation logs. This is why detections search for both.

##### `net localgroup`

```cmd
net localgroup
net localgroup administrators
```
- Without arguments, lists all local groups. With a group name, lists its members.
- Checking the local *Administrators* group tells the attacker which accounts (local or domain) have admin rights on this host, which become targets for credential theft.

##### `query user`

```cmd
query user
```
- Lists the users with an active session on the host (console or RDP), with their session ID, state, idle time, and logon time.
- It queries the *Remote Desktop Services* session manager. `quser` is the same tool.
- Attackers use it to check whether a user is actively working at the machine, and to find logged-in privileged users whose credentials are in memory.

##### `Get-LocalUser`

```powershell
Get-LocalUser | Select-Object Name, Enabled, LastLogon, PasswordLastSet
```
- The PowerShell equivalent of `net user`. It returns local accounts as objects, so they can be filtered and sorted.
- It comes from the `Microsoft.PowerShell.LocalAccounts` module (Windows PowerShell 5.1+).
- `Get-LocalGroupMember Administrators` is the equivalent of `net localgroup administrators`.

---
### System and Apps

Attackers enumerate the system and installed applications to find vulnerabilities, or applications to steal data from.
- Maps to [T1082 - System Information Discovery](https://attack.mitre.org/techniques/T1082/), [T1057 - Process Discovery](https://attack.mitre.org/techniques/T1057/), [T1518 - Software Discovery](https://attack.mitre.org/techniques/T1518/), and [T1007 - System Service Discovery](https://attack.mitre.org/techniques/T1007/).

##### `tasklist`

```cmd
tasklist /v
```
- Lists running processes with their PID, memory usage, and with `/v` (verbose) also the owning user, status, and window title.
- `/svc` shows the services hosted inside each process instead.
- Attackers look for security tools (EDR or AV agents) and for applications of interest, like password managers, browsers, or database clients.

> Check out [[Investigating Processes]] for the defensive use of the same tools.

##### `systeminfo`

```cmd
systeminfo
```
- Displays the OS name, version and build, install date, last boot time, domain membership, installed hotfixes, and network adapters.
- It collects this mainly from *WMI* classes such as `Win32_OperatingSystem` and `Win32_QuickFixEngineering`.
- The hotfix list shows which patches are missing. Attackers feed this output into exploit suggesters to find privilege escalation vulnerabilities.

##### `wmic product`

```cmd
wmic product get name,version
```
- Lists installed software with its version, which can then be matched against known vulnerabilities.
- It queries the `Win32_Product` WMI class, which only covers software installed through *Windows Installer* (MSI).
- `wmic` is deprecated on recent Windows builds. The PowerShell equivalent is `Get-CimInstance Win32_Product`.

> Querying `Win32_Product` makes Windows Installer run a consistency check on every MSI package, which is slow and writes an `MsiInstaller` event (`1035`) per product to the *Application* log. This is a noisy, detectable side effect. Reading the `HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall` registry key is a quieter alternative.

##### `Get-Service`

```powershell
Get-Service | Where-Object Status -eq 'Running'
```
- Lists the services on the host with their name, display name, and status.
- It queries the *Service Control Manager*.
- Attackers look for security services to disable, and for services they can abuse for persistence or privilege escalation.
- `Get-Service` doesn't show the binary path. `Get-CimInstance Win32_Service | Select-Object Name, PathName, StartName` does, which reveals unquoted service paths and services running as *SYSTEM*.

---
### Network Settings

Attackers inspect the network settings to find out if the host belongs to a corporate network, and what else they can reach from it.
- Maps to [T1016 - System Network Configuration Discovery](https://attack.mitre.org/techniques/T1016/) and [T1049 - System Network Connections Discovery](https://attack.mitre.org/techniques/T1049/).

##### `ipconfig`

```cmd
ipconfig /all
```
- Displays the configuration of every network adapter: [[IP]] address, subnet mask, default gateway, DHCP server, and DNS servers.
- The *DNS suffix* usually reveals the corporate domain name, and in a domain environment the DNS servers are usually the [[Domain Controller]]s.

##### `netstat`

```cmd
netstat -ano
```
- Lists all active connections and listening [[Port]]s.
- `-a` shows all connections and listening ports, `-n` shows numeric addresses instead of resolving names, and `-o` shows the owning PID.
- Established connections reveal internal servers the host talks to, like file shares, databases, or the [[Domain Controller]], which are candidates for lateral movement.

##### `netsh advfirewall`

```cmd
netsh advfirewall show allprofiles
```
- Shows the state of the Windows Firewall for each of the three profiles: *Domain*, *Private*, and *Public*.
- Windows applies the *Domain* profile only when it can reach a [[Domain Controller]] of the domain it is joined to. An active Domain profile confirms the host is on the corporate network.
- It also shows whether the firewall is enabled and its default inbound and outbound policy, which tells the attacker if C2 traffic or lateral movement will be blocked.

---
### Active Antivirus

Attackers check for the active antivirus to find out how risky it is to continue the attack without being blocked.
- Maps to [T1518.001 - Security Software Discovery](https://attack.mitre.org/techniques/T1518/001/).

##### `SecurityCenter2` WMI Query

```powershell
Get-WmiObject -Namespace "root\SecurityCenter2" -Query "SELECT * FROM AntivirusProduct"
```
- Lists the antivirus products registered with *Windows Security Center*, with their `displayName`, `pathToSignedProductExe`, and `productState`.
- AV vendors register their product in the `root\SecurityCenter2` WMI namespace, and this query reads that registration.
- `productState` is a bitmask that encodes whether the product is enabled and whether its signatures are up to date.
- `Get-WmiObject` was removed in PowerShell 7. `Get-CimInstance -Namespace root\SecurityCenter2 -ClassName AntivirusProduct` is the modern equivalent.

> `SecurityCenter2` only exists on workstation editions of Windows, not on Windows Server. On servers, attackers fall back to checking processes and services (`tasklist`, `Get-Service`) or `Get-MpComputerStatus` for Microsoft Defender.

---
