### General Notes

This is an application on the Domain Controller that allows for managing the objects of the Active Directory.
- There is a list that shows a hierarchical diagram of all the users, computers, and groups that exist in this domain within containers called _organization units_.
- **Organizational Units OUs** are logical *container objects*.

---
### Organizational Units (OUs)

An _OU_ is used to define a set of users with similar policy requirements.
- OU's provide a hierarchical structure to AD enabling admins to organize resources based on the organization's structure.
- OUs can contain other OUs.
- A user can be part of only one OU at a time.

There are also some default OUs that are created by Windows:
- **Builtin**: This contains default groups that are available to all Windows hosts.
- **Computers**: This contains any machine that joins the network.
- **Domain Controllers**: This contains the DCs of the network.
- **Users**: Contains the users and groups.
- **Managed Services Accounts**: Holds the accounts used by services in the windows domain.

> OUs are protected against deletion. To allow deletion, the advanced features option from the view menu needs to be enabled. We right click the OU we need, and go to its properties. There we can allow deletion by unchecking protect from accidental deletion.

##### Delegating Control of an OU

To delegate control of an OU to a certain user, right click on the OU and choose delegate control.
- There, the user that should get these permissions is chosen, and the actions that they can do can be chosen.

##### Difference between OUs and [[Active Directory#Security Groups|Security Groups]]

**OUs** are handy for **applying policies** to users and computers.
- This includes specific configurations that pertain to sets of users depending on their particular role in the enterprise.
- A user can only be a member of a single OU at a time.

**Security Groups**, are used to **grant permissions over resources**.
- For example, you will use groups if you want to allow some users to access a shared folder or network printer.
- A user can be a part of many groups, which is needed to grant access to multiple resources.

---
