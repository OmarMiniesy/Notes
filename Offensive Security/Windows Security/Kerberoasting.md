### General Notes

This is a *post exploitation* attack that targets the [[Kerberos]] authentication protocol in [[Active Directory]], and specifically, the *Ticket Granting Service (TGS)* ticket.
- The attacker here is after the service account password that is used to encrypt the TGS.
- This is mapped to the [[MITRE ATT&CK]] sub-technique `T1558.003`.

> This allows the attacker to impersonate an account; giving access to the system, services, networks, and anything else that the account is entitled to.

Some of the essential concepts to know for this attack are:
###### Ticket Granting Service (TGS)

By supplying the *SPN* of the service, the *Key Distribution Center (KDC)* issues a ticket for a user to be able to access that specific service.
- This ticket contains the user's data requesting the service.
- This ticket is encrypted using the service account's [[NTLM]] password hash by the KDC. This is the service account key.
- That way, when the service receives the TGS ticket that is encrypted with its own password, it can decrypt it and check the user that is requesting it.  

> Since the TGS ticket is encrypted with the service account’s key, attackers target SPNs to get their TGS tickets to crack.

###### Service Principal Name (SPN)

Kerberos uses [[Active Directory#Service Principal Name (SPN)|Service Principal Names (SPNs)]] to associate the service with its service logon account to be able to obtain the password.
- The KDC will look up the SPN, finds the service account for that service, and encrypts the TGS ticket with the account key. 

> Host based accounts, or computer accounts that end in dollar signs, `$` are not vulnerable to Kerberoasting attacks given their long and complex passwords.

---
### Attack Flow

> The attacker must have already gotten access to a user account to be able to do this.

1. An attacker first enumerates SPNs in the domain.

This indicates that the discovered service is mapped to an account, which the attacker can steal the password of. This can be done by using tools like `powerview`.

2. The attacker then requests a TGS ticket for the targeted SPNs from the KDC.

This can be done using tools like `Rubeus` or `GetUserSPNs.py`. Any [[Objects#Users|Domain User]] can perform this action of requesting TGS tickets.

Using `Rubeus` and specifying the `kerberoast` action and an output file for the discovered SPNs.
```powershell
Rubeus.exe kerberoast /outfile:spn.txt
```

3. The attacker receives the TGS ticket from the KDC.

Some part of the TGS ticket is encrypted using the service account key. This encrypted blob is the target of the attackers to crack.

4. The attacker starts to crack the credential hash of the SPN *offline*.

The attacker uses offline tools like [[John the Ripper]] or `hashcat` to crack the password. This is done without contacting the [[Domain Controller]].

Using `hashcat` with mode `13100`:
```bash
hashcat -m 13100 -a 0 <spn.txt> <passwords-dictionary.txt> --outfile="cracked.txt"
```
- The mode of `13100` for Kerberoastable TGS tickets.
- The `spn.txt` file with the output from Rubeus containing the accounts to have their hashes cracked.
- The output file `cracked.txt` to dump the cracked passwords.
- Can use the `--force` argument if an error is returned.

Using [[John the Ripper]] with the format of `krb5tgs`
```bash
sudo john spn.txt --fork=4 --format=krb5tgs --wordlist=passwords.txt
```
- To increase cracking speed, we added 4 parallel process using `fork`.

5. If the attacker succeeds and extracts the password, the attacker can login into the service account.

This gives the attacker access to any service, network, system, and permissions that the compromised service account has. The attacker can now start to steal data, escalate privileges, or set [[Backdoors]].

---
### Prevention

To prevent this attack, the following techniques can be implemented:
- Limiting the number of accounts with SPNs.
- Disable accounts that are no longer used/needed.
- Ensure strong passwords to counter the brute force cracking mechanisms. (100+ characters)
- The usage of *Group Managed Service Accounts (GMSA)*, which are service accounts that are managed by [[Active Directory]] and cannot be user anywhere except their designated server.
	- The password of these accounts are rotated automatically.

### Detection

Since the first part of this attack involves identifying target service accounts, we can monitor [[Lightweight Directory Access Protocol (LDAP)]] activity, specially for [[Domain Reconnaissance]] activity.
- Check out [[BloodHound#Detecting Bloodhound Usage|LDAP Filters]] for filters on LDAP usage in reconnaissance.
- For SPN querying, we can use the filter in the `SearchFilter` field in [[SilkETW]] output channel. Check out [[Splunk Queries#Detecting Recon by BloodHound]] for guidance.
```
*(&(samAccountType=805306368)(servicePrincipalName=*)*
```

Another detection idea is to understand the difference between Kerberoasting activity and normal activity.
- For both, TGS tickets for services will be requested, but only in normal activity will the user login after the TGS is requested.
- For Kerberoasting, this is not the case, as the attacker wants to crack the password.
- We cam group all TGS request events by the same user and checking if there are logon events after these TGS request events.

To detect this attack, we can utilize [[Windows Events Log]] logs with Event ID `4769`.
- This log is generated when TGS are requested.
- This log is generated when a user attempts to access a service.
- The log contains the ticket encryption type, which can be `AES`, `RC4`, or `DES`. If it is `0x17`, then it is `RC4` which is vulnerable to Kerberoasting. `0x1` and `0x3` are `DES` and are also vulnerable.
- This event is generated a lot of times, so we should group it by the user requesting tickets and from which machine the tickets were requested from to see any abnormal behavior. Also filtering on the encryption type, to see if any type that is abnormal is being used in the environment.

The normal [[Kerberos]] authorization flow can also be useful by monitoring these [[Windows Events Log]] Event IDs:
- `4768`: This is the Kerberos TGT request event.
- `4769`: This is the Kerberos TGS request sent by the client for the needed service.
- `4624`: This is the logon event when the user successfully logs in to the service.

Looking also for the *account name* that is not a machine account (not ending with `$`), and the *service name* also not being a machine account is also useful.
- This is because machine accounts request TGS tickets all the time.
- This is because service machine accounts will have large and complex passwords so it would be hard to crack them.

To detect this using [[Splunk]]:
```
Event.EventData.TicketEncryptionType="0x17" Event.System.EventID="4769" Event.EventData.ServiceName!="*$" | table Event.EventData.ServiceName, Event.EventData.TargetUserName, Event.EventData.IpAddress
```

> Logs can be found in `Windows Logs/Security`.

Another good detection technique is having a *honeypot user*. This is a user with no real value but they appear like a good target for an attacker. If logs are generated for this user, then we know that an attacker has infiltrated the system. Some qualities of the honeypot user are:
- Relatively old user.
- Strong password that hasn't been changed recently.
- Have some privileges assigned to it to make it interesting.
- Account must have an SPN registered. `IIS` and `SQL` accounts are good options.

---
