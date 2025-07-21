
### Security Principals

An object that can be authenticated, and is represented with a unique SID (security identifier).
- It is an object that can be assigned permissions.

### SIDs

These are unique identifiers for security principals and security groups.
- every object has an SID that is issued by the Domain Controller and stored in a secure database.
- SIDs can be used once, even after the security principle is no longer in use.
- There are [well known SIDs](https://ldapwiki.com/wiki/Wiki.jsp?page=Well-known%20Security%20Identifiers) that are used for generic users and groups across all AD environments.

For ex, users when they are logged in get an access token that has their SID and all the SIDs they are groups of.

---
