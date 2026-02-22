### General Notes

This is an attack technique used to obtain [[Kerberos]] *TGT*s by using stolen password hashes.
- Here, the [[NTLM]] hash is used to request a TGT from the [[Domain Controller]].
- The attacker uses the password hash to create a Kerberos ticket to be able to move laterally within the network and access other services.

---
### Attack Path

The attacker uses a tool to extract the [[NTLM]] hash of a user that is currently logged in on the compromised system.
- The attacker needs to be *local administrator* at least to be able to do this
```powershell
mimikatz # sekurlsa::logonpasswords
```

The attacker then crafts a new AS-REQ request for a the user to request a TGT ticket.
- Does not require elevated privileges.
```powershell
.\Rubeus.exe asktgt /user:<user> /domain:<domain> /rc4:<NTLM-HASH> ptt
```
- Here we used `rc4` as this is the format of the dumped hash.

Can also use Mimikatz:
```powershell
mimikatz # sekurlsa::pth /user:<user /domain:<domain> /ntlm:<hash>
```

> Now, the attacker has a TGT and is fully authenticated with [[Kerberos]], allowing requests to other services.

---
### Detection

Similar to detecting [[Pass the Hash#Detection|Pass the Hash]] when running the Mimikatz tool.

For Rubeus, we need to look for communication with the [[Domain Controller]] on [[Port]] 88 starting from an unusual process.
- Legitimate [[Kerberos]] traffic originates from [[Windows Processes#`lsass.exe`|LSASS.exe]], which is not the case through Rubeus.
- Check out [[Splunk Queries#Detecting Overpass the Hash]]

---
