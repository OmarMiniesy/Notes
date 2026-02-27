### General Notes

This is a stateless authentication [[Protocol]] based on the use of *tickets* instead of transmitting passwords over the network.
- Used by [[Active Directory]].
- Uses [[Port]] 88 both [[Transport Layer|TCP and UDP]].

##### `krbtgt` Service Account

This is a built in service account for the *Key Distribution Center (KDC)* that is automatically created. 
- All the [[Domain Controller]]s share the same `krbtgt` password.
- It cannot be deleted and the account name cannot be changed.
- The `krbtgt` account's password hash is the one used to derive the secret key that encrypts and signs the *TGT*, and only the DCs know this secret key.
- The TGT is what is used to request service tickets from the resources in the domain.

> The weakness of the `krbtgt` is that if this account is compromised, attackers can generate and forge tickets and they can impersonate any user. This is the [[Golden Ticket]] attack.

Some important notes:
 - Unusual RC4 usage in Event ID `4769` → possible [[Kerberoasting]].    
- TGS with high-privilege PAC → Silver Ticket suspicion.

---
### Authentication Process

When a user logs in, their password is used to encrypt a timestamp, which is sent to the *Key Distribution Center (KDC)* to verify the integrity of the authentication by decrypting it. 
- The KDC is a service usually installed on the [[Domain Controller]] in charge of creating Kerberos tickets on the network.
- The KDC service on the DC checks the authentication service request *AS-REQ*, verifies the user information, and creates a *Ticket Granting Ticket (TGT)*, which is delivered to the user.

> When a TGT is requested, [[Windows Events Log]] generates a log with Event ID `4768`.

The TGT is encrypted with the secret key of the `krbtgt` account and sent to the user. This is the *AS-REP*.
- This *TGT* is used to request service tickets for accessing network resources, allowing authentication without repeatedly transmitting the user's credentials.
- Along with the TGT, a *Session Key* is given to the user as part of the content of the TGT, which they will need to generate the following requests.

> The TGT is encrypted using the `krbtgt` account's password hash, and therefore the user can't access its contents.

The user then presents the TGT to the DC, requesting a *Ticket Granting Service (TGS)* ticket for a specific service.
- To request a TGS, the user will send their username and a timestamp encrypted using the Session Key, along with the TGT and a [[Active Directory#Service Principal Name (SPN)|SPN]] which indicates the service and server name we intend to access.
- This is the *TGS-REQ*. If the TGT is successfully validated, its data is copied to create a TGS ticket. 
- Sent along with TGS is the *service session key*, which is used to authenticate to the service of choice.

> When a TGS is requested, [[Windows Events Log]] generates a log with Event ID `4769`. This log is also generated when a user attempts to connect to a service.

The TGS is encrypted with a secret key derived from the [[NTLM]] password hash of the service that the user wants to connect to and is delivered to the user in the *TGS_REP*.
- The user presents the TGS to the service, and if it is valid, the user is permitted to connect to the resource. This is the *AP_REQ*.
- The *service session key* is also checked by decrypting the TGS and ensuring its value.

> The TGS is encrypted using a key derived from the password of the service being requested so that only the service can decrypt the ticket and verify it. 

---
### Delegation

Delegation basically delegates a service account to access resources/services on behalf of a [[Objects#Users|User]], which extends a user identity to the back-end server.
- This allows the user to get access to content without having to be assigned access.
- There are 3 types of delegation, *constrained*, *unconstrained*, and *resource based*.

1. **Unconstrained delegation** allows an account to delegate to any service. This is a “collector box” that automatically saves the keys (TGTs) of anyone who connects to it.
2. **Constrained delegation** allows services to delegate user credentials only to specified resources. Any user or computer accounts that have service principal names (SPNs) set in their `msDS-AllowedToDelegateTo` property can impersonate any user in the domain to those specific SPNs.
3. **Resource-based delegation** places the configuration at the delegated object side. That is, the service account that is to be delegated has stored which accounts can delegate to it.

When *unconstrained delegation* is enabled, when a user requests a *TGS* ticker for a service, the [[Domain Controller]] will embed the user's *TGT* into the *TGS*.
- That way, when connecting to the remote service, the user will present both the TGS and the TGT.
- That way, when the service needs to authenticate to another service on behalf of the user, it will present the user's *TGT* it has.

---
