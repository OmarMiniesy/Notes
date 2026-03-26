### General Notes

This is an attack where threat agents can generate [[Kerberos]] tickets for any [[Objects#Users|User]] in the domain.
- The attacker here acts as a [[Domain Controller]] and impersonates the `domain administrator` role.

This attack exploits the fact that:
1. The Kerberos `krbtgt` service account has the same password across all Domain Controllers.
2. This password is used to sign all the Kerberos tickets produced by the Key Distribution Center.
3. This password's hash is the most trusted object in the entire Domain because it is how objects guarantee that the environment's Domain issued Kerberos tickets.

#### Impact

If an attacker has the password hash of the `krbtgt` account, forged Kerberos TGTs can be created that are *valid*. 
- Since these forged ticket are signed by the secret of the `krbtgt` account, they are trusted by the Domain Controller.
- The attacker can create tickets for any user, even administrators, because the DC only checks the signature of the ticket.

Since there is a [[Trees, Forests, and Trusts#Trust Relationships|two-way transitive trust]] relationship between domains in a [[Trees, Forests, and Trusts#Forests|Forest]], forged TGTs in one domain can be used to request services in another domain.
- This can be used to forge tickets to escalate rights from child domain to a parent domain in the same forest.

The password history value for the `krbtgt` account is 2. Therefore it stores the two most recent passwords. 
- By resetting the password twice, we effectively clear any old passwords from the history, so there is no way another DC will replicate this DC by using an old password.

---
### Attack Path - [adsecurity](https://adsecurity.org/?page_id=1821#KERBEROSGolden)

The attack can be conducted using `Mimikatz` and by specifying this list of arguments:
- `/domain`: the target domain name
- `/sid`: the target domain [[Objects#SIDs|SID]].
- `/rc4`: the password hash of the `krbtgt` account.
- `/user`: the user that will be impersonated. *Mimikatz* will generate a ticket for this user.
- `/id`: the [[Objects#RIDs|RID]] of the user to be impersonated. Some users have default *RIDs*, like the *administrator* user.
- `/renewmax`: The maximum number of days the forged ticket can be renewed.
- `/endin`: This is the end of life for the ticket, or ticket lifetime.

To obtain the *SID* of the target domain, we can use `Get-DomainSID` by  [PowerView](https://github.com/darkoperator/Veil-PowerView).
```powershell
powershell -exec bypass
.\PowerView.ps1
Get-DomainSID
```

To obtain the password `rc4` hash of the `krbtgt` account, one technique we can use is the [[DCSync]] attack if we have an account with the necessary permissions.
- We can use `Mimikatz` and specify the target domain and the `krbtgt` user.
```powershell
mimkatz.exe
lsadump::dcsync /domain:<domainname> /user:krbtgt
```
- This will output the [[NTLM]] hash of the `krbtgt` user.

> Another technique to obtain the hash of the `krbtgt` account is to view `NTDS.dit` and [[Windows Processes#`lsass.exe`|LSASS]] process dumps on the [[Domain Controller]].

Now we can use *Mimikatz* tool with all of this information to obtain a golden ticket for the *Administrator* user.
- The `/ptt` argument makes `Mimikatz` pass the ticket into the current session.
```powershell
mimikatz.exe

kerberos::golden /domain:<domainname> /sid:<sidvalue> /rc4:<hash> /user:Administrator /id:500 /renewmax:7 /endin:8 /ptt
```

> We can then check the list of [[Kerberos]] tickets in the current session using the `klist` command.

---
### Prevention & Detection

We monitor for [[Windows Events Log]] events with ID `4769`, which mean that a [[Kerberos]] service ticket was created.
- We can then correlate with the client requesting the ticket and the service, and see if there is any abnormality
- The service could be the `krbtgt` service.

Another essential thing to do is to look for TGS requests with no preceding TGT requets. This is because for golden tickets, the TGT is forged locally.
- Find `4769` events with no matching `4768` from the same account within a reasonable time window (e.g., 10 hours — the default TGT lifetime)

Another idea to look for is accounts that logon with high privileges using event ID `4672`.
- Look for accounts that are logging in with permissions that they shouldn't have.
- So an non-admin account triggering `4762` is suspicious.

If `SID filtering` is enabled, we will get alerts with the event ID `4675` during cross-domain escalation.

We can also monitor for the extraction of the `krbtgt` hash by checking for:
- a [[DCSync]] attack.
- `NTDS.dit` file access. (check out [[Domain Controller#NTDS.DIT|NTDS.dit]])
- [[Windows Processes#`lsass.exe`|LSASS]] memory read via [[Sysmon]] event ID `10`.

> Can also be detected via the same techniques as [[Pass the Ticket]], check out [[Splunk Attack Specific Queries#Detecting Pass the Ticket]].

|Priority|Detection|
|---|---|
|🔴 Critical|4769 with no preceding 4768 for same account|
|🔴 Critical|RC4 encryption (0x17) in 4769 in an AES-enforced domain|
|🟠 High|4769 ticket lifetime exceeding domain policy|
|🟠 High|4624 Type 3 from account with no 4768 on any DC|
|🟡 Medium|4672 for unexpected accounts correlated with above|
|🟡 Medium|4662 (DCSync) in the same time window — attacker getting krbtgt|

---
