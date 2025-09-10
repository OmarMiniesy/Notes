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

> Managed by [[Domain Controller]]s.

There are 2 protocols that are used for authentication in Windows domains.
- [[Kerberos]]: this is the default protocol that is used now. Uses [[Port]] 88 for both TCP and UDP.
- [[NTLM]]: this protocol is legacy. 

---
### Service Principal Name (SPN)

This is used to uniquely identify an instance of a service.
- Each instance of the same service has a unique SPN.

---
### DNS

AD [[Domain Name System (DNS)]] is used by private networks to facilitate communications between devices (servers, clients, ...)
- AD has a database with DNS records called *Service Records (SRV)*.
- Dynamic DNS is used to automatically update the DNS database.

When a client joins the network, the [[Domain Controller]] is located by:
1. Sending a DNS query to the DNS service.
2. The service retrieves the SRV record for the DC.
3. It then transmit the DC hostname to the client, which then uses it to get the IP address of the DC.

> DNS uses [[Transport Layer|TCP & UDP]] [[Port]] 53. UDP by default, but it changes to TCP for messages larger than 512 bytes.

---
### Domain Cached Credentials

In the case that the [[Domain Controller]]s are unreachable, *Domain Cached Credentials (DCC)* are used, using the MSCache2 algorithm.
- A host will save the last 10 hashes for any domain users that successfully authenticated in the `HKEY_LOCAL_MACHINE\SECURITY\CACHE` [[Windows Registry]] key.
- Cannot be used in pass the hash attacks and are hard to brute force.

This is how they look:
```
$DCC2$10240#bjones#e4e938d12fe5974dc42a90120bd9c90f
```

---
### Active Directory Certificate Services - AD CS - [Certificate Vulnerabilities](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)

This is the server that allows the AD to have a public key cryptographic infrastructure with [[Digital Signatures]] and [[Certificates]].

The certificate has the following fields:
- *Subject* - The owner of the certificate.
- *Public Key* - Associates the Subject with a private key stored separately.
- *NotBefore* and *NotAfter* dates - Define the duration that the certificate is valid.
- *Serial Number* - An identifier for the certificate assigned by the CA. 
- *Issuer* - Identifies who issued the certificate (commonly a CA).
- *SubjectAlternativeName* - Defines one or more alternate names that the Subject may go by.
- *Basic Constraints* - Identifies if the certificate is a CA or an end entity, and if there are any constraints when using the certificate.
- *Extended Key Usages (EKUs)* - Object identifiers (OIDs) that describe how the certificate will be used. Common EKU OIDs include: 
	- Code Signing (OID 1.3.6.1.5.5.7.3.3) - The certificate is for signing executable code. 
	- Encrypting File System (OID 1.3.6.1.4.1.311.10.3.4) - The certificate is for encrypting file systems. 
	- Secure Email (1.3.6.1.5.5.7.3.4) - The certificate is for encrypting email. 
	- Client Authentication (OID 1.3.6.1.5.5.7.3.2) - The certificate is for authentication to another server (e.g., to AD).
	- Smart Card Logon (OID 1.3.6.1.4.1.311.20.2.2) - The certificate is for use in smart card authentication.
	- Server Authentication (OID 1.3.6.1.5.5.7.3.1) - The certificate is for identifying servers (e.g., [[HTTPS]] certificates).
- *Signature Algorithm* - Specifies the algorithm used to sign the certificate.
- *Signature* - The signature of the certificates body made using the issuer’s (e.g., a CA’s) private key.

---
