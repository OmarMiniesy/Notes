### General Notes

This is a protocol used for authentication against directory services like [[Active Directory]]. It is how systems in the network communicate with AD.
- Uses [[Port]] 389
- LDAP over *SSL*, LDAPS uses port 636

> LDAP is the [[Protocol]] used by the Active Directory servers and clients.

LDAP Authentication uses credentials using a `BIND` operation. There are two types of LDAP authentication:
- *Simple Authentication*: A username and password are used to create a `BIND` request to authenticate to LDAP server.
- *SASL Authentication*: A framework that uses other authentication services, like [[Kerberos]], to bind to the LDAP server, and then to authenticate to LDAP. The LDAP protocol is used to send messages with challenge/response packets to authenticate.

> LDAP authentication is done in cleartext.

---
