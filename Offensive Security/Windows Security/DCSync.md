### General Notes

This attack is where attackers impersonate [[Domain Controller]]s and request [[Domain Controller#Replication|Replication]] data from a target domain controller.
- This works because DCs replicate user account data between them to ensure synchronized changes.
- So if an attacker manages to convince a DC into giving them this replication data, they can extract the *password hashes*.

However, for an account to request replication, these permissions need to exist:
- `Replicating Directory Changes`
- `Replicating Directory Changes All`

> These permissions are granted to *Domain Admins*, *Enterprise Admins*, and the *SYSTEM* account.

Once the attacker has extracted the hashed passwords, the following can take place:
- Crack the passwords offline using tools like [[John the Ripper]].
- Perform [[Pass the Hash]] attacks, which are when the attacker simply places the hashed password as is during requests. The ciphertext is enough, the attacker does not need to know the plaintext.

---
### Attack Path

First, we need to obtain access to a user with the permissions that are specified above.
- Once that is done, we can then start with the attack scenario.

We can run a command prompt *as* the identified user with the necessary permissions:
```powershell
runas /user:<username> cmd.exe
```
- This runs the `cmd.exe` as the user specified.

Now, we can use the tool `Mimikatz` which can be used to implement the *DCSync* attack.
```powershell
mimkatz.exe

lsadump::dcsync /domain:<domainname> /user:<targetusername>
```
- We specify the domain we are targeting, and the username that we want to obtain the password of.
- The `user` can be `/all` if we want to dump the hashes of the entire [[Active Directory]] environment.

---
### Prevention & Detection

We can prevent this attack using an *RPC Firewall* which will allow replications only between Domain Controllers.

We can detect this attack by detecting the Event ID of `4662` from [[Windows Events Log]], which logs on Domain Controller replications.
- We can then check the *Account Name* that performed the replication. If it is not a Domain Controller username, we know immediately that the attack took place.

To minimize false positives, we can check 
- If the *Properties* field has either of these Control Access Rights:
	- `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2`
	- `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2`
- We can also whitelist certain accounts, like `Azure AD Connect`.

---
