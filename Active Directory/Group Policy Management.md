### General Notes

To efficiently manage the [[Active Directory/Active Directory|Active Directory]] network and the resources inside, we utilized [[Active Directory Users and Computers#Organizational Units (OUs)|Organizational Units (OUs)]].
- That way, different departments of the organization inside the network can be easily managed.

The policies that are defined for OUs to allow and prevent actions is managed through _Group Policy Objects (GPOs)_.
- GPOs are a collection of settings that can be applied to an OU.
- These settings target all types of resources, like users and machines.

---
### GPO Management

The _Group Policy Management_ tool is used to configure these GPOs.
- GPOs are first created here, and they are linked to the needed OU.

> The GPO will apply both to the OU, and to any sub-OUs under it.

To apply the GPO to a specific set of computers/users in the OU, use _security filtering_.
- By default, the settings are applied to all the users and computers in the OU, which are present in the **authenticated users** group.

---
### GPO Distribution

GPOs are distributed across the network using a _shared directory_ called `SYSVOL`, that is stored in the _Domain Controller_.
- This shared directory stores files and information that must be replicated among Domain Controllers in a domain.
- All users in the domain should have access to this share via the network to be able to sync their GPOs.

This share is located at `C:\\\\Windows\\\\SYSVOL\\\\sysvol\\\\` in the domain controller.
- This path has subfolders for each domain in the active directory.
- There is a `Policies` folder that has the GPOs for that domain.

---