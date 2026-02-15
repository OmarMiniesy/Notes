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

In the case that the [[Domain Controller]]s are unreachable, *Domain Cached Credentials (DCC)* are used, using the *MSCache2* algorithm.
- A host will save the last 10 hashes for any domain [[Objects#Users|Users]] that successfully authenticated in the `HKEY_LOCAL_MACHINE\SECURITY\CACHE` [[Windows Registry]] key.
- Cannot be used in *pass the hash attacks* and are hard to brute force.

This is how they look:
```
$DCC2$10240#bjones#e4e938d12fe5974dc42a90120bd9c90f
```

---
