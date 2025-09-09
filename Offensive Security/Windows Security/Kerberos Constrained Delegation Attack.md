### General Notes

If an attacker owns - knows the password - to a service account, the attacker can impersonate any user to the services that are trusted by this service account for delegation.
- The services being accessed trust that the service account is allowed to delegate on behalf of the user.

> The attacker goes to the KDC as this service account, *pretends to be another user*, and asks for a ticket to access a specific service as that impersonated user.

###### Delegation
[[Kerberos]] delegation basically delegates a service account to access resources/services on behalf of a [[Objects#Users|User]], which extends a user identity to the back end server.
- This allows the user to get access to content without having to be assigned access.
- There are 3 types of delegation, *constrained*, *unconstrained*, and *resource based*.

**Unconstrained delegation** allows an account to delegate to any service. This is a “collector box” that automatically saves the keys (TGTs) of anyone who connects to it.
**Constrained delegation** allows a user account to have specified the services they can delegate to. 
**Resource-based delegation** places the configuration at the delegated object side. That is, the service account that is to be delegated has stored which accounts can delegate to it.

---
### Attack Path

First, we need to start by finding all the accounts in [[Active Directory]] that have constrained delegation enabled.
- These accounts are allowed to impersonate other users when accessing specific services.
- This can be done using [PowerView's](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1) `Get-NetUser`.

```powershell
Get-NetUser -TrustedToAuth
```

We will see the name of the account, along with the `msds-allowedtodelegateto` attribute.
- This shows the service type, the host where the service lies, and the domain in order separated by `/` as shown below.
```
msds-allowedtodelegateto: {http/DC1.eagle.local/eagle.local}
```

> Any attacker that gains access to the account that has this delegation attribute can ask the KDC for a ticket as the *Domain Admin* for `HTTP/DC1.eagle.local`. Now, the attacker has a [[Kerberos]] ticket that makes them domain admin whenever they connect to that HTTP service at that [[Domain Controller]], DC1.

Now that we know what the account can delegate to, we can abuse that for privilege escalation and act as Domain Admins.
- But first, we need a Kerberos ticket.
- This service ticket will allow the attacker to access the resources/services up for delegation.
- This can be done using `Rubeus`:

To generate a ticket, the attacker will pretend to be the compromised service account that can delegate, and asks for a ticket as an elevated user to the specified resource.
```powershell
.\Rubeus.exe s4u 
    /user:<compromised-service-account> 
    /rc4:<service-account-hash> 
    /domain:<domainname>
    /impersonateuser:Administrator 
    /msdsspn:"http/dc1" 
    /dc:dc1.eagle.local 
    /ptt
```
- The `s4u` is the function that abuses the constrained delegation.
- The `user` has the compromised service account.
- The `rc4` has the [[NTLM]] hash of the service account. This is used by `Rubeus` to authenticate as the `user` specified.
- The `domain` name.
- The user to be impersonated in `impersonateuser`.
- The `msdsspn` has the service we will impersonate ***to***.
- The `dc` has the [[Domain Controller]] we will talk to.
- The `ptt` injects the generated ticket into shell session to use directly.

> We can then check that the ticket was generated using the `klist` command.

Now that the ticket is generated, we can connect to the Domain Controller and impersonate the `Administrator` account.
```powershell
Enter-PSSession <domaincontrollername>
```

---
### Prevention & Detection

There are some protections against this but they are not enabled by default.
- Configure the property `Account is sensitive and cannot be delegated` for all privileged users.
- Add privileged users to the `Protected Users` [[Objects#Security Groups|Groups]]: this membership automatically applies the protection mentioned above.

To detect this, we should have a baseline and know the normal behavior of users, and check if their access to certain resources is done at abnormal times or from abnormal machines.

Successful logons with delegated tickets will show data about the ticket issuer in the `Transited Services` attribute.
- This shows the account that was used to generate the ticket.
- The account that can be delegated.