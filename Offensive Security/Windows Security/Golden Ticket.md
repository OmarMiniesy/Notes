### General Notes

This is an attack where threat agents can generate [[Kerberos]] tickets for any [[Objects#Users|User]] in the domain.
- The attacker here acts as a [[Domain Controller]].

This attack exploits the fact that:
1. The Kerberos `krbtgt` service account has the same password across all Domain Controllers.
2. This password is used to sign all the Kerberos tickets produced by the Key Distribution Center.

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

To obtain the password hash of the `rc4` account, one technique we can use is the [[DCSync]] attack if we have an account with the necessary permissions.
- We can use `Mimikatz` and specify the target domain and the `krbtgt` user.
```powershell
mimkatz.exe
lsadump::dcsync /domain:<domainname> /user:krbtgt
```
- This will output the [[NTLM]] hash of the `krbtgt` user.

Now we can use *Mimikatz* tool with all of this information to obtain a golden ticket for the *Administrator* user.
- The `/ptt` argument makes `Mimikatz` pass the ticket into the current session.
```powershell
mimikatz.exe

kerberos::golden /domain:<domainname> /sid:<sidvalue> /rc4:<hash> /user:Administrator /id:500 /renewmax:7 /endin:8 /ptt
```

We can then check the list of [[Kerberos]] tickets in the current session using the `klist` command.

---
### Prevention & Detection

We monitor for [[Windows Events Log]] events with ID `4769`, which mean that a [[Kerberos]] service ticket was created.
- We can then correlate with the client requesting the ticket and the service, and see if there is any abnormality
- The service could be the `krbtgt` service.

If `SID filtering` is enabled, we will get alerts with the event ID `4675` during cross-domain escalation.

---
