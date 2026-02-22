### General Notes

Tis is an attack where attackers can use the [[NTLM]] password hash instead of the actual plain text password to authenticate.

The attacker modifies credential material inside the **LogonSession** in [[Windows Processes#`lsass.exe`|LSASS.EXE]].  
That is the defining signal of Pass-the-Hash.
- Windows does **not** create an ordinary interactive logon.
- No password is provided.
- The attacker **forces LSASS** to believe a session has different credentials.

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

> Check out [[Splunk Queries#Detecting Pass the Hash]].

Mimikatz accesses the `LSASS` process memory, check out [[Windows Processes#`lsass.exe`|lsass.exe]], and changes the `LogonSession` information in the access token.
- This is a process access event and can be identified using [[Sysmon]] event ID 10.

We also need to correlate with login events (`4624`) with the following characteristics:
- *logon_type* `9`, which is for `NewCredentials`. 
	- This is when a process creates a new logon session using supplied credentials but does not authenticate to the local machine. Triggered by `Mimikatz sekurlsa::pth`.
- We also need to hunt for `Logon_Process = seclogo`.
	- This is the logon pipeline used when windows creates a network only credential token, which is the behavior observed during pass the hash attacks.

This behavior is similar in nature to `runas /netonly`, where the same logon type of 9 is produced.
- The credentials are only used for remote authentication, and locally, still the same user.
- However, there is no process access event generated as LSASS is not touched here.

---
