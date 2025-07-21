### Windows Domains

A windows domain is a group of users and computers under a single administration.
- This is a centralized system for managing and securing users, computers, and devices in a network.
- Domains have *Organizational Units OUs* inside.

This single repository that allows the administration of the components of a Windows network is called the _Active Directory (AD)_.
- The AD is the underlying service that provides for Windows domains.
- It is like a read only database accessible by all users in the domain regardless of privilege level.
- There can be many domains in the case of a larger organization, each with its own systems and computers.

*AD* is a distributed, hierarchical structure that allows centralized management of an organization's resources, including users, computers, groups, network devices and file shares, group policies, devices, and trusts. 
- *AD* provides authentication, accounting, and authorization functionalities within a Windows enterprise environment. 
- It also allows administrators to manage permissions and access to network resources.

---
### Active Directory Domain Services (AD DS)

The _AD DS_ is the core of the Windows domain, and it acts as a catalogue that holds information about the objects in the network.
- This acts as the central database of the domain.
- The AD DS manages the rights of users on the network to access information and resources.

At the core of the Windows domain, is the _Domain Controller_.
- This is a server responsible for running the *Active Directory Services.*
- It is the central authority for the domain.

> A *Directory Service* is a database system that stores, organizes, and provides access to information about users, devices, applications, and resources in a network.

---
#### Objects and Attributes

A resource inside AD is called an *object*. All objects have *attributes* that define its characteristics.
- All attributes have an associated *LDAP* name that can be used through LDAP queries.
- This [list](https://learn.microsoft.com/en-us/windows/win32/adschema/attributes-all) has all of the attributes used by AD.

The *GUID*, or Global Unique Identifier is a unique `128` bit value assigned to an object on creation.
- It is used to represent an object and it is stored in the `objectGUID` attribute.
- When looking for an object in the AD, the GUID is what to use.
- The GUID never changes and it can never be removed from the object as long as the object exists in the domain.

The *Distinguished Name, (DN)*, is the full path to an AD object.
The *Relative Distinguished Name, (RDD)*, is taking one component of the *DN* and using to identify the object from other objects at the same level.
- Two objects cannot have the same DN, but they can have the same RDN.

A *container object* is a type of object that can hold and organize other objects.
A *leaf object* is a type of object that does not contain another object.

The *schema* defines what types of objects exist in the AD database and all its associated attributes.
- This schema can be used by applications to understand what objects and properties are available.
- This schema can be updated dynamically by modifying the schema object in the directory.

Some of the objects supported by _AD_ are:
- Domain Users
- Domain Computers
- Domain Group Information
- [[Active Directory Users and Computers#Organizational Units (OUs)| Organizational Units (OUs)]]
- Default Domain Policy
- Functional Domain Levels
- Password Policy
- [[Group Policy Management|Group Policy Objects (GPOs)]]
- Groups
- Machines
- Shares
- [[Trees, Forests, and Trusts#Trust Relationships|Domain Trusts]]
- Access Control Lists (ACLs)

> To configure users, groups, and machines in Active Directory, the [[Active Directory Users and Computers]] application needs to be run from the Domain Controller.

##### Users

A user is an entity that represents an individual, a service, or an application that requires certain access privileges.
- Each user is saved as an object and contains attributes to identify its identity, its permissions, and its settings.

Users are also known as _security principles_.
- A security principle is an object that can act upon other resources in the network.
- However, they need to have the right permissions and privileges to be able to access these network resources.

##### Machines

A machine is used to represent a computer in the AD domain.
- Machines are also considered as _security principles_.

When a machine is added to the domain, a _machine account_ is created for it in the AD.
- This allows the machine to interact with the domain and participate in the network.
- Machine accounts have their own identities and credentials.

> Machine accounts are local administrators on the assigned computer.

Machine accounts follow a naming scheme.
- The machine account is the name of the computer followed by a dollar sign.

##### Security Groups

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
