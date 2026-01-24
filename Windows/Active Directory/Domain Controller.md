### General Notes

At the core of the Windows domain, is the _Domain Controller_.
- This is a server responsible for running the *Active Directory Services.*
- It is the central authority for the domain.

> To identify Domain Controllers in a network, check out [[Identifying Hosts#Identifying Domain Controller s|Identifying DCs in Wireshark]].

The *Default Domain Controllers policy* is created automatically with a domain and sets baseline security and auditing settings for all domain controllers in a given domain.

> A *Directory Service* is a database system that stores, organizes, and provides access to information about users, devices, applications, and resources in a network.

There can be several DCs in one AD network each with different roles:
- [[#FSMO (Flexible Single Master Operation) Roles]]
- [[#Global Catalog (GC)]]
- [[#Read-Only Domain Controller (RODC)]]

> [[Domain Controller]]s are trusted by default for *unconstrained delegation*.

###### Active Directory Domain Services (AD DS)

The _AD DS_ is the core of the Windows domain, and it acts as a catalogue that holds information about the objects in the network.
- This acts as the central database of the domain.
- The AD DS manages the rights of users on the network to access information and resources.

###### Replication

This is when AD [[Objects]] are updated and transferred from one DC to another.
- When DCs are added, connection objects are created by the KCC (Knowledge Consistency Checker) service that is present on all DCs, to manage replication.
- This feature is used to ensure that changes are always synchronized between DCs.

###### SYSVOL

A folder that stores copies of public files in the domain. This shared directory stores files and information that must be replicated among Domain Controllers in a domain.
- *Policies folder*: System policies, [[Group Policy Object]] and [[Group Policy Object#Group Policy Preferences|Group Policy Preferences]] settings.
- *Scripts folder*: logon/logoff scripts, other script types
- The content of the SYSVOL folder is replicated to the DCs within the environment using the *File Replication Service (FRS)*.

> This share is located at `C:\\\\Windows\\\\SYSVOL\\\\sysvol\\\\` in the domain controller.

###### NTDS.DIT

This file is stored on a DC at `C:\Windows\NTDS\` and is a database.
- Stores information about users, groups, memberships, and password hashes for all domain users.

> If the setting `Store password with reversible encryption` is enabled, then it also stores the cleartext version of the password.

---
### FSMO (Flexible Single Master Operation) Roles

Domain Controllers are the ones that can change data in the AD database, but since there are several DCs in the network, there needs to be a process through which writes & reads processes don't conflict.
- They introduced roles that are not bound to a single DC, known as *FSMO* roles.

There are 5 roles that are assigned to the first DC in the forest root domain. *Sysadmin* can transfer the needed roles after.
- *Schema master*: One per [[Trees, Forests, and Trusts#Forests|Forest]], and it is responsible for managing the *AD Schema*.
- *Domain naming master*: One per forest, and it is responsible for managing the domain names. Making sure that no 2 domains in the same forest have the same name.
- *RID (Relative ID) master*: One per domain that is responsible for allocating RIDs to other objects, and ensuring their uniqueness.
- *PDC(Primary Domain Controller) emulator*: One per domain, and it is the DC that responds to authentication requests, password changes, and managing [[Group Policy Object]]s. It also maintains time for the domain.
- *Infrastructure master*: One per domain, and it is responsible for managing communication between domains in a single forest. It translates *GUIDs, SIDs*, and *DNS* between domains. If this is not properly functions, the *ACLs* will show *SIDs* instead of resolved names.

---
### Global Catalog (GC)

This is a *domain controller* that has copies of all the [[Objects]] in the AD [[Trees, Forests, and Trusts#Forests|Forest]]. It stores a full copy of objects belonging to the current domain, and a partial copy of objects belonging to other domains.
- A standard domain controller has a complete replica of all the objects belonging only to its domain. The GC allows users and applications to find information about objects in any domain in the forest.
- This is a feature that is enabled on a domain controller.

---
### Read-Only Domain Controller (RODC)

This *Domain Controller* has a read only database, and no passwords are cached here other than the `RODC` computer account and the `RODC KRBTGT` passwords. It has the following features:
- A read only *DNS* server
- Allows for administrator role separation
- Reduces replication traffic
- Prevents `SYSVOL` modifications from being replicated to other DCs.

---
