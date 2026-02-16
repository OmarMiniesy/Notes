### General Notes

[[Active Directory]] [[Active Directory#Windows Domains|domain]] reconnaissance is a stage where the adversary tries to gather information about the targeted environment, such as:
- Architecture
- Network topology
- Security measures
- Potential vulnerabilities
- [[Domain Controller]]s
- [[Objects#Users|User Accounts]]
- [[Group Policy Object]]s

> [[BloodHound]] is a tool that can be used for reconnaissance as well. It uses [[Lightweight Directory Access Protocol (LDAP)]] queries.

---
### Reconnaissance using Native Windows Executables

> To try and detect these techniques, we can enable PowerShell script block logging and monitoring for execution of scripts or cmdlets. It has an Event ID of `4104`. Also, check out [[Splunk Queries#Detecting Domain Reconnaissance using Native Windows Binaries]].
##### `net group`

The command `net group` command can be used to identify the [[Objects#Security Groups|Groups]] present as well as the users of a certain group in the current domain.
- To obtain the best information, adding the `/domain` runs this command against the [[Domain Controller]]. Avoiding it runs the command against the local machine.

To list all the groups on the [[Active Directory#Windows Domains|domain]]:
```powershell
net group /domain
```

To view the members of a specific group:
```powershell
net group "group-name" /domain
```
- To show all *Domain Administrators*, we will place it in the group name.

> A similar utility to use is `net user` which does the exact same thing but for *users* instead of *groups*.

##### Other Techniques

Using `whoami /all` displays full security context of the current user, displaying attributes for the user object like:
- Username
- SID
- Groups
- Privileges 

Using `wmic computersystem get domain` gets information about the current machine's domain status and currently joined domain.

Using [[Address Resolution Protocol (ARP)]] reconnaissance, by viewing the ARP cache table through the command `arp -a`.
- This is helpful to showcase the recently communicated hosts which can include [[Domain Controller]]s.

Using `nltest /domain_trusts` to enumerate the [[Trees, Forests, and Trusts#Trust Relationships|Trust Relationships]], which allows for accessing of resources across domains.

---
