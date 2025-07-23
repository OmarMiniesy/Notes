
### Security Principals

An object that can be authenticated, and is represented with a unique SID (security identifier).
- It is an object that can be assigned permissions.

### SIDs

These are unique identifiers for security principals and security groups.
- every object has an SID that is issued by the Domain Controller and stored in a secure database.
- SIDs can be used once, even after the security principle is no longer in use.
- There are [well known SIDs](https://ldapwiki.com/wiki/Wiki.jsp?page=Well-known%20Security%20Identifiers) that are used for generic users and groups across all AD environments.

For ex, users when they are logged in get an access token that has their SID and all the SIDs they are groups of.

### sAMAccountName

This is the user's logon name.
- It must be unique within the domain and with length less than or equal to 20.

### userPrincipalName

This is another username for the user object that is composed of their account name followed by the domain name.

### FSMO (Flexible Single Master Operation) Roles

Domain Controllers are the ones that can change data in the AD database, but since there are several DCs in the network, there needs to be a process through which writes & reads processes don't conflict.
- They introduced roles that are not bound to a single DC, known as FSMO roles.

There are 5 roles that are assigned to the first DC in the forest root domain. Sysadmin can transfer the needed roles after.
- Schema master: One per forest
- Domain naming master: One per forst
- RID master: One per domain
- PDC(Primary Domain Controller) emulator: One per domain
- Infrastructure master: One per domain

### Global Catalog (GC)

This is a domain controller that has copies of all the objects in the AD forest. It stores a full copy of objects belonging to the current domain, and a partial copy of objects belonging to other domains.
- A standard domain controller has a complete replica of all the objects belonging only to its domain. The GC allows users and applications to find information about objects in any domain in the forest.
- This is a feature that is enabled on a domain controller.

### Read-Only Domain Controller (RODC)

This Domain Controller has a read only database, and no passwords are cached here other than the RODC computer account and the RODC KRBTGT passwords. It has the following features:
- A read only DNS server
- Allows for administrator role separation
- Reduces replication traffic
- Prevents SYSVOL modifications from being replicated to other DCs.

### Replication

This is when AD objects are updated and transferred from one DC to another.
- When DCs are added, connection objects are created by the KCC (Knowledge Consistency Checker) service that is present on all DCs, to manage replication.
- This feature is used to ensure that changes are always synchronized.

### Service Principal Name (SPN)

This is used to uniquely identify an instance of a service.
- Each instance of the same service has a unique SPN.

### ACL Access Control List

A collection of Asset Control Entries.

### ACE Access Control Entry

This identifies a trustee and lists the access rights (allow, deny, audit) given to that trustee.
- A trustee can be a user account, a group account, a session,...

All ACEs have the following:
- A security identifier (SID) that identifies the trustee to which the ACE applies.
- An access mask that specifies the access rights controlled by the ACE.
- A flag that indicates the type of ACE.
- A set of bit flags that determine whether child containers or objects can

### Discretionary Access Control List (DACL)

Defines which security principles are granted/denied access to objects by holding a list of ACEs.
- If an object does not have a DACL, the system grants access to anyone.
- If an object has a DACL with no ACE entries, the system denies access to anyone.
- If an object has a DACL with some ACE entries, the ACEs are checked in sequence until a match is found that allows the requested rights, or until no match is found and access is denied.

### System Access Control Lists (SACL)

This allows the logging of access attempts made to secure objects.
- An ACE is used to specify what type of access attempts are to generate logs.

### Fully Qualified Domain Name (FQDN)

This is the complete name for a computer or host:
```
[host name].[domain name].[tld]
```

Similar to DNS, it allows locating hosts in AD without knowing the IP address.

### SYSVOL

A folder that stores copies of public files in the domain. It is shared on an NTFS volumne on all the DCs in a domain, and contains:
- Policies folder: System policies, group policy settings
- Scripts folder: logon/logoff scripts, other script types

The content of the SYSVOL folder is replicated to the DCs within the environment using the File Replication Service (FRS).

### NTDS.DIT

This file is stored on a DC at `C:\Windows\NTDS\` and is a database.
- Stores information about users, groups, memberships, and password hashes for all domain users.

> If the setting `Store password with reversible encryption` is enabled, then it also stores the cleartext version of the password.

### AdminSDHolder

This is an object that provides template permissions for the protected accounts and groups in the domain.
- It is automatically created in the System container of every AD domain.
- The `SDProp` process runs every hour on the Domain Controller that holds the PDC Emulator. It compares the permissions on the AdminSDHolder object with permissions of protected account and groups in the domain, and restores them to match the AdminSDHolder object. 

> Protected accounts and groups are special objects where permissions are set and enforced via an automatic process that ensures the permissions on the objects remain consistent.

### dsHeuristics

This is a string value attribute used to define forest-wide configurations.
- One setting it allows is excluding built-in groups from the protected groups list.
- Groups excluded via the dsHeuristics aren't affected once the `SDProp` process runs.

### adminCount

An attribute that determines whether or not the `SDProp` process protects the user.
- If 0 or not set, then it is not protected.
- If 1, then it is protected. (they are usually privileged accounts).
