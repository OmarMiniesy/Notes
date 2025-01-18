### Windows Domains

A windows domain is a group of users and computers under a single administration.

- This is a centralized system for managing and securing users, computers, and devices in a network.

This single repository that allows the administration of the components of a Windows network is called the _Active Directory (AD)_.

- The AD is the underlying service that provides for Windows domains.
- There can be many domains in the case of a larger organization, each with its own systems and computers.

At the core of the Windows domain, is the _Domain Controller_.

- This is a server responsible for running the Active Directory services.
- It is the central authority for the domain.

The Active Directory inside the Windows domain allows for:

- Centralized identity management.
- Management of security policies.

---

### Active Directory Domain Services (AD DS)

The _AD DS_ is the core of the Windows domain, and it acts as a catalogue that holds information about the objects in the network.

- This acts as the central database of the domain.

Some of the objects supported by _AD_ are:

- Users
- Groups
- Machines
- Shares

> To configure users, groups, and machines in Active Directory, the [[Active Directory Users and Computers]] application needs to be run from the Domain Controller.

### Users

A user is an entity that represents an individual, a service, or an application that requires certain access privileges.

- Each user is saved as an object and contains attributes to identify its identity, its permissions, and its settings.

Users are also known as _security principles_.

- A security principle is an object that can act upon other resources in the network.
- However, they need to have the right permissions and privileges to be able to access these network resources.

### Machines

A machine is used to represent a computer in the AD domain.

- Machines are also considered as _security principles_.

When a machine is added to the domain, a _machine account_ is created for it in the AD.

- This allows the machine to interact with the domain and participate in the network.
- Machine accounts have their own identities and credentials.

> Machine accounts are local administrators on the assigned computer.

Machine accounts follow a naming scheme.

- The machine account is the name of the computer followed by a dollar sign.

### Security Groups

A group is an object that can contain other objects, like users, machines, or other groups.

- The permissions of the objects inside the security group are inherited from the permissions of the security group itself.
- Security groups are also considered _security principles_.

There are some default security groups that are created in a domain.

- **Domain Admins**: Users in this group have admin privileges over the entire domain, including the Domain Controllers (DCs).
- **Server Operators**: Users in this group can only administer the DCs. They do not have authority over group memberships.
- **Backup Operators**: Users in this group can access any file, disregarding their permissions.
- **Account Operators**: Users of this group can create or modify other accounts.
- **Domain Users**: All the user accounts in the domain.
- **Domain Computers**: All computers of the domain.
- **Domain Controllers**: All the domain controllers of the domain.

---
