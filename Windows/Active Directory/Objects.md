### General Notes

A resource inside AD is called an *object*. All objects have *attributes* that define its characteristics.
- All attributes have an associated *LDAP* name that can be used through LDAP queries.
- This [list](https://learn.microsoft.com/en-us/windows/win32/adschema/attributes-all) has all of the attributes used by AD.

The *schema* defines what types of objects exist in the [[Active Directory]] database and all its associated attributes.
- This schema can be used by applications to understand what objects and properties are available.
- This schema can be updated dynamically by modifying the schema object in the directory.

###### GUIDs
The *GUID*, or Global Unique Identifier is a unique `128` bit value assigned to an object on creation.
- It is used to represent an object and it is stored in the `objectGUID` attribute.
- When looking for an object in the AD, the GUID is what to use.
- The GUID never changes and it can never be removed from the object as long as the object exists in the domain.

###### Security Principles
A *security principle* is an object that can act upon other resources in the network.
- It is an object that is securable and can be assigned permissions and rights.
- An *SID* is a unique identifier for security principals and security groups. 

###### SIDs
Every object has a *unique SID* that is issued by the [[Domain Controller]], stored in a secure database, and can only be used once even if the principle is no longer in use.
- There are [well known SIDs](https://ldapwiki.com/wiki/Wiki.jsp?page=Well-known%20Security%20Identifiers) that are used for generic users and groups across all AD environments.
- For ex, users when they are logged in get an access token that has their SID and all the SIDs they are groups of.

###### Object Names

The *Distinguished Name, (DN)*, is the full path to an AD object.
The *Relative Distinguished Name, (RDD)*, is taking one component of the *DN* and using to identify the object from other objects at the same level.
- Two objects cannot have the same DN, but they can have the same RDN.

The *Fully Qualified Domain Name (FQDN)* is the complete name for a computer or host:
```
[host name].[domain name].[tld]
```
- Similar to DNS, it allows locating hosts in AD without knowing the IP address.

###### Object Types

A *container object* is a type of object that can hold and organize other objects.
A *leaf object* is a type of object that does not contain another object.

Some of the objects supported by _AD_ are:
- Domain Users
- Domain Computers
- Domain Group Information
- [[Active Directory Users and Computers#Organizational Units (OUs)| Organizational Units (OUs)]]
- Default Domain Policy
- Functional Domain Levels
- Password Policy
- [[Group Policy Object]]s
- Groups
- Machines
- Shares
- [[Trees, Forests, and Trusts#Trust Relationships|Domain Trusts]]
- Access Control Lists (ACLs)

> To configure users, groups, and machines in Active Directory, the [[Active Directory Users and Computers]] application needs to be run from the Domain Controller.

---
### Users

A user is an entity that represents an individual, a service, or an application that requires certain access privileges.
- Each user is saved as an object and contains attributes to identify its identity, its permissions, and its settings.
- A user is a _leaf object_.
- Users have _SIDs (Secure IDs)_ and _GUIDs_.
- Users are _security principles_.

Some attributes for users:
- `sAMAccountName` :  This is the user's logon name. It must be unique within the domain and with length less than or equal to 20.
- `userPrincipalName` :  This is another username for the user object that is composed of their account name followed by the domain name.

---
### Machines

A machine is used to represent a computer in the AD domain.
- Machines are also considered as _security principles_.
- They are also considered _leaf objects_.
- They have an _SID_ and a _GUID_.

When a machine is added to the domain, a _machine account_ is created for it in the AD.
- This allows the machine to interact with the domain and participate in the network.
- Machine accounts have their own identities and credentials.

> Machine accounts are local administrators on the assigned computer.

Machine accounts follow a naming scheme.
- The machine account is the name of the computer followed by a dollar sign.

---
### Security Groups

A group is an object that can contain other objects, like users, machines, or other groups.
- The permissions of the objects inside the security group are inherited from the permissions of the security group itself.
- Security groups are also considered _security principles_.

There are some default security groups that are created in a domain.
- **Domain Admins**: Users in this group have admin privileges over the entire domain, including the [[Domain Controller]]s (DCs).
- **Server Operators**: Users in this group can only administer the DCs. They do not have authority over group memberships.
- **Backup Operators**: Users in this group can access any file, disregarding their permissions.
- **Account Operators**: Users of this group can create or modify other accounts.
- **Domain Users**: All the user accounts in the domain.
- **Domain Computers**: All computers of the domain.
- **Domain Controllers**: All the domain controllers of the domain.

> The default security groups are held in the _built-in_ container.

---
### Access Control Lists

A collection of *Asset Control Entries (ACEs)*
- This identifies a trustee and lists the access rights (allow, deny, audit) given to that trustee.
- A trustee can be a user account, a group account, a session,...

All ACEs have the following:
- A security identifier (SID) that identifies the trustee to which the ACE applies.
- An access mask that specifies the access rights controlled by the ACE.
- A flag that indicates the type of ACE.
- A set of bit flags that determine whether child containers or objects can

###### Discretionary Access Control List (DACL)
Defines which security principles are granted/denied access to objects by holding a list of ACEs.
- If an object does not have a DACL, the system grants access to anyone.
- If an object has a DACL with no ACE entries, the system denies access to anyone.
- If an object has a DACL with some ACE entries, the ACEs are checked in sequence until a match is found that allows the requested rights, or until no match is found and access is denied.

###### System Access Control Lists (SACL)
This allows the logging of access attempts made to secure objects.
- An ACE is used to specify what type of access attempts are to generate logs.

---
