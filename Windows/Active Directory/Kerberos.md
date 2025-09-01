### General Notes

This is a stateless authentication [[Protocol]] based on the use of *tickets* instead of transmitting passwords over the network.
- Used by [[Active Directory]].
- Uses [[Port]] 88 both [[Transport Layer|TCP and UDP]].

##### `krbtgt` Service Account

This is a built in service account for the *Key Distribution Center (KDC)* that is automatically created. All the [[Domain Controller]]s share the same `krbtgt` password.
- It cannot be deleted and the account name cannot be changed.
- The `krbtgt` account's password hash is the one used to encrypt and sign the *TGT*.
- The TGT is what is used to request service tickets from the resources in the domain.

> The weakness of the `krbtgt` is that if this account is compromised, attackers can generate and forge tickets and they can impersonate any user. This is the [[Golden Ticket]] attack.

---
### Authentication Process

When a user logs in, their password is used to encrypt a timestamp, which is sent to the *Key Distribution Center (KDC)* to verify the integrity of the authentication by decrypting it. 
- The KDC is a service usually installed on the [[Domain Controller]] in charge of creating Kerberos tickets on the network.
- The KDC service on the DC checks the authentication service request *AS-REQ*, verifies the user information, and creates a *Ticket Granting Ticket (TGT)*, which is delivered to the user.

The TGT is encrypted with the secret key of the `krbtgt` account and sent to the user. This is the *AS-REP*.
- This *TGT* is used to request service tickets for accessing network resources, allowing authentication without repeatedly transmitting the user's credentials.
- Along with the TGT, a *Session Key* is given to the user as part of the content of the TGT, which they will need to generate the following requests.

> The TGT is encrypted using the `krbtgt` account's password hash, and therefore the user can't access its contents.

The user then presents the TGT to the DC, requesting a *Ticket Granting Service (TGS)* ticket for a specific service.
- To request a TGS, the user will send their username and a timestamp encrypted using the Session Key, along with the TGT and a [[Active Directory#Service Principal Name (SPN)|SPN]] which indicates the service and server name we intend to access.
- This is the *TGS-REQ*. If the TGT is successfully validated, its data is copied to create a TGS ticket.
- Sent along with TGS is the *service session key*, which is used to authenticate to the service of choice.

> When a TGS is requested, [[Windows Events Log]] generates a log with Event ID `4769`. This log is also generated when a user attempts to connect to a service.

The TGS is encrypted with the [[NTLM]] password hash of the service or computer account in whose context the service instance is running and is delivered to the user in the *TGS_REP*.
- The user presents the TGS to the service, and if it is valid, the user is permitted to connect to the resource *AP_REQ*.
- The *service session key* is also checked by decrypting the TGS and ensuring its value.

---
