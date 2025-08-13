### General Notes

This is a post exploitation attack that targets the [[Kerberos]] authentication protocol in [[Active Directory]], and specifically, the *Ticket Granting Service (TGS)* ticket.
- The attacker here is after the service account password that is used to encrypt that TGS.

> This allows the attacker to impersonate an account; giving access to the system, services, networks, and anything else that the account is entitled to.

Some of the essential concepts to know for this attack are:

###### Ticket Granting Service (TGS)

By supplying the SPN of the service, the *Key Distribution Center (KDC)* issues a ticker for a user to be able to access that specific service.
- This ticket contains the user's data requesting the service.
- This ticket is encrypted using the service account's [[NTLM]] password hash by the KDC. This is the service account key.
- That way, when the service receives the TGS ticket that is encrypted with its own password, it can decrypt it and check the user that is requesting it.  

> Since the TGS ticket is encrypted with the service account’s key, attackers target SPNs to get their TGS tickets to crack.

###### Service Principal Name (SPN)

Kerberos uses [[Active Directory#Service Principal Name (SPN)|Service Principal Names (SPNs)]] to associate the service with its service logon account to be able to obtain the password.
- The KDC will look up the SPN, finds the service account for that service, and encrypts the TGS ticket with the account key.  

---
### Attack Flow

1. An attacker first enumerates SPNs in the domain.

This indicates that the discovered service is mapped to an account, which the attacker can steal the password of.

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
### Prevention & Detection

To prevent this attack, the following techniques can be implemented:
- Limiting the number of accounts with SPNs.
- Disable accounts that are no longer used/needed.
- Ensure strong passwords to counter the brute force cracking mechanisms. (100+ characters)
- The usage of *Group Managed Service Accounts (GMSA)*, which are service accounts that are managed by [[Active Directory]] and cannot be user anywhere except their designated server.
	- The password of these accounts are rotated automatically.


To detect this attack, we can utilize [[Windows Events Log]] logs with Event ID `4769`.
- This log is generated when TGS are requested.
- This log is generated when a user attempts to access a service.
- The log contains the ticket encryption type, which can be `AES`, `RC4`, or `DES`.
- This event is generated a lot of times, so we should group it by the user requesting tickets and from which machine the tickets were requested from to see any abnormal behavior. Also filtering on the encryption type, to see if any type that is abnormal is being used in the environment.

> Logs can be found in `Windows Logs/Security`.

Another good detection technique is having a *honeypot user*. This is a user with no real value but they appear like a good target for an attacker. If logs are generated for this user, then we know that an attacker has infiltrated the system. Some qualities of the honeypot user are:
- Relatively old user.
- Strong password that hasn't been changed recently.
- Have some privileges assigned to it to make it interesting.
- Account must have an SPN registered. `IIS` and `SQL` accounts are good options.

---
