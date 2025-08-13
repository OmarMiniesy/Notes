### General Notes

This is an attack similar to the [[Kerberoasting]] attack that also targets the [[Kerberos]] [[Active Directory]] authentication protocol.
- This attack targets [[Objects#Users|User]] accounts that have the property `Do not require Kerberos preauthentication` enabled to obtain their hashed passwords and crack them.
###### *Kerberos Preauthentication*

Normally, a user account that has this property enabled forces the user to prove they know their password before the *KDC*, *Key Distribution Center*, can give them anything useful.
- If this property is disabled, then the requesting user does not need to prove their identity to the KDC, and the KDC replies with data that is encrypted with the requesting user's password.

Therefore, an attacker needs to send a fake logon request, *AS-REQ* to a KDC acting as a user that has *Kerberos Preauthentication* disabled.
- The KDC replies with the *AS-REP* encrypted with the user's password. This response contains the *TGT*.
- This _AS-REP_ also contains the *TGT (Ticket Granting Ticket)* which is normally only given to authenticated users — but here the attacker forces its creation without needing to know the password.
- The attacker then takes this _AS-REP_ and attempts to crack the user password offline using a tool like `hashcat` or [[John the Ripper]].

---
### Attack Flow

The attacker must first find users that have *Kerberos Preauthentication* disabled, which can be done using `Rubeus` using the `asreproast` action.
```powershell
Rubeus.exe asreproast /outfile:asrep.txt
```

Once the tool extracts the user hashes, we need to modify the output such that `hashcat` can crack the encryption.
- We do this by adding `23$` after `krb5asrep$` in the output file.

Now, we can use `hashcat` with the mode `18200`
```bash
sudo hashcat -m 18200 -a 0 <asrep.txt> <password-dictionary.txt> --outfile asrepcrack.txt --force
```
- The file `asrep.txt` has the user hashes output from `Rubeus` that we modified by adding `23$`.
- A password dictionary file like `rockyou.txt`.
- The output for `hashcat` is to be saved in the `asrepcrack.txt` file.

---
### Prevention & Detection

Make sure that the accounts with the property `Kerberos Preauthentication` are reviewed regularly and have strong password policies.

Since the attacker instigates the creation of a *TGT*, we can use the [[Windows Events Log]] Event with ID `4768` which creates a log when a *TGT* is requested.
- The tool `Rubeus` will cause these logs to be generated.
- We can filter these logs with the location the authentication was generated from, which can help detect good logins from malicious logins.

> Logs can be found in `Windows Logs/Security`.

Another good detection technique is having a *honeypot user*. This is a user with no real value but they appear like a good target for an attacker. If logs are generated for this user, then we know that an attacker has infiltrated the system. Some qualities of the honeypot user are:
- Should not be the only user with the property `Kerberos Preauthentication` disabled.
- Should be relatively old user.
- The password should be maintained, so for service accounts it should be over 2 years older, and for regular users it should *not* be older than 1 year.
- Account must have logins after the day the password was changed.
- Account should have some privileges to be interesting.

---
