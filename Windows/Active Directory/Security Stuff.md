
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

---


