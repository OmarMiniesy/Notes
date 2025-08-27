### General Notes

To efficiently manage the [[Active Directory|Active Directory]] network and the resources inside, we utilized [[Active Directory Users and Computers#Organizational Units (OUs)|Organizational Units (OUs)]].
- That way, different departments of the organization inside the network can be easily managed.

The policies that are defined for OUs to allow and prevent actions is managed through _Group Policy Objects (GPOs)_.
- GPOs are a collection of policy settings that can be applied to an OU.
- These settings target all types of resources, like users and machines.

##### Order of Precedence

GPOs are processed using this order of precedence:
1. Local security policy: The policies are defined directly to the host locally outside the domain
2. Site policy: Any policies specific to the Enterprise Site that the host resides in.
3. Domain policy: Policies applied on the domain level as a whole.
4. Parent OU policy
5. Child OU policy

Exceptions to this ordering
- If a GPO is set at the domain level with the `Enforced` option selected, the settings contained in that GPO will be applied to all OUs in the domain and cannot be overridden by lower-level OU policies.
- It is also possible to set the `Block inheritance` option on an OU. If this is specified for a particular OU, then policies higher up (such as at the domain level) will NOT be applied to this OU. 
- If both options are set, the `No Override` option has precedence over the `Block inheritance` option.

> Child OU have the highest priority, while Local policies have the lowest. If there are conflicting settings, the policy down the line is the one that wins. The order above is only the order they are processed.

##### Group Policy Preferences

These allow administrators to configure additional settings, and can be managed by the users directly.
- The preferences are applied through client side extensions and are refreshed when Group Policy is updated.
- There are several types of [Client-Side Extensions](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/group-policy/group-policy-preferences#client-side-extensions) that are used for configurations.
- Allows filtering and targeting specific items, and can be used with Boolean logic.

---
### GPO Refreshing

When a new GPO is created, the settings aren't applied directly.
- They are applied during periodic group updates which are done every 90 minutes by default with a random offset of 30 mins.
- For [[Domain Controller]], this period is only 5 minutes.

This default refreshing can be changed, and can be ran directly using the command:
```
gpupdate /force
```
- Compares the GPOs on the machine with those on the Domain Controller and does updates as needed.

---
### GPO Management

The _Group Policy Management_ tool is used to configure these GPOs.
- GPOs are first created here, and they are linked to the needed OU.
- Can also be done using PowerShell `GroupPolicy` module.

> The GPO will apply both to the OU, and to any sub-OUs under it.

To apply the GPO to a specific set of computers/users in the OU, use _security filtering_.
- By default, the settings are applied to all the users and computers in the OU, which are present in the **authenticated users** group.

The *Default Domain Policy* is the default GPO that is automatically created and linked to a domain.
- Has the highest precedence of all applied GPOs.

---
### GPO Distribution

GPOs are distributed across the network using the _shared directory_ [[Domain Controller#SYSVOL|SYSVOL]].
- All users in the domain should have access to this share via the network to be able to sync their GPOs.

---
### [Policy Types](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/security-policy-settings)

*Account Policies* are used to manage how user accounts interact with the domain.
- Include the password policy, account lockout policy, and [[Kerberos]] related settings like ticket lifetimes.

*Local Polices* are used to manage a specific computer.
- Include the [[Windows Events Log]] audit policy, user privileges on the host, network security controls, ability to install drivers, whether guests/administrator accounts are enabled, and more.

*Software Restriction Policies* are used to control what software is allowed to run on the host.

*Application Control Policies* are used to control which users/groups can run which applications.
- Administrators can also use [Applocker](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/applocker-overview).

*Advanced Audit Policy* is used to adjust the activities that are audited.

---
### GPO Security

The GPO permissions should be locked down to ensure only a very particular [[Objects#Security Groups|Group]] can modify it or change its permissions.
- The GPO permissions should be regularly reviewed, even having an automated task that regularly runs to checks deviations.

GPO modification can be detected using the [[Windows Events Log]] with Event ID `5136` only if *Directory Service Changes* auditing is enabled.

> `auditpol.exe` can be used to configure the auditing policies.

---
