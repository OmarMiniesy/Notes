### General Notes

Sometimes, credentials can be stored in Windows Shares for any purpose.
- These shares can then be made public, or have the wrong permissions assigned to the share, putting these credentials out and in risk.

Credentials can be found in network shares within scripts and configuration files like: 
- `batch`
- `cmd`
- `PowerShell`
- `conf`
- `ini`
- `config`
 
In contrast, credentials on a user's local machine primarily reside in:
- Text files
- Excel sheets
- Word documents

###### Windows Shares
A Windows *Share* is a local folder on a computer that is accessible via the network by other computers and users.
- It allows multiple users to read, write, and execute files in a shared folder depending on their permissions.

Shares with `$` at the end of their names in Windows are *hidden or administrative shares*. The `$` hides them from normal network browsing. 
- However, they are still accessible if someone knows the exact share name and has the proper permissions: `\\ComputerName\\ShareName$`.
- Users can also create their own hidden shares as well.

---
### Attack Path

The first step is identifying all the shares that exist in the domain. This can be done using `Invoke-ShareFinder` by [PowerView](https://github.com/darkoperator/Veil-PowerView).
```PowerShell
Import-Module .\PowerView.ps1
Invoke-ShareFinder -domain <domain> -ExcludeStandard -CheckShareAccess
```
- First, specify the domain to be searched.
- Then, we exclude out the default shares.
- Then, we check if the current user has access to the identified shares.

To execute this attack, we first need to:
1. Open PowerShell as administrator user.
2. Set *Execution Policy* to *Unrestricted*:
```powershell
Set-ExecutionPolicy Unrestricted -Scope CurrentUser
```

Once we have identified the shares, we need to parse all the files present on the shares and check for passwords.
- The tool [SauronEye](https://github.com/vivami/SauronEye) to find specific keywords in files.
- A manual approach using `findstr` built in command.

Using `findstr`:
- `/s` forces to search the current directory and all subdirectories.
- `/i` ignores case in the search term.
- `/m` shows only the filename for a file that matches the term. Removing this option returns the exact line that matches.
- The `term` that defines what we are looking for. 
- Good candidates include `pass`, `pw`, and the `NETBIOS` name of the domain. Using the domain name returns nice results as it is present in `runas` and `net` commands which take passwords as arguments.
- Attractive targets for this search would be file types such as `.bat`, `.cmd`, `.ps1`, `.conf`, `.config`, and `.ini`.
```powershell
findstr /m /s /i "pass" *.bat
findstr /m /s /i "pass" *.config
findstr /m /s /i "pass" *.cmd
findstr /m /s /i "pass" *.ini
findstr /m /s /i "pw" *.config
findstr /m /s /i "administrator" *.ps1
findstr /m /s /i "domainname" *.ps1
```
Once a file is identified, we can use the command `Get-Content` with the filename to print out its content.
- This is another way to simply using `cat <filename>`.

---
### Prevention & Detection

Ensuring that all shares have the right access permissions, and running regular scans to check if any scripts or files have exposed credentials.

Checking to see if login attempts, either successful or failed were attempted for accounts that are not normal for these accounts.
- Checking on [[Windows Events Log]] events with Event ID `4624` and `4625` for successful and failed logins respectively.
- Also checking on Event ID `4768` for a [[Kerberos]] *TGT* request.

Another method is to detect the tool that searches for all the exposed shares, `Invoke-ShareFinder`.
- We can check to see that there will be many connections done to many computers by a single attacking workstation.

We can add a honeypot service account with a fake incorrect password in a script that seems realistic.
- The honeypot user account should have the password changed before the last file modification date so the attacker doesn't suspect the password is incorrect.
- Once the attacker tries to log in, we can detect failed authentication using these event IDs on that honeypot account:
	- `4625`
	- `4771`: The *failure code* of `0x18` indicates wrong password.
	- `4776`: The *error code* of `0xC000006A` indicates bad password.

---

