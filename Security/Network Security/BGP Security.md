### General Notes

The security for the external gateway [[Protocol]] BGP important for [[Networking/Routing|Routing]] depends on several factors:
- The routers themselves that share information are manually configured by humans.
- Since it uses TCP for communication, it is vulnerable to TCP attacks such as [[TCP Session Hijacking]], [[SYN Flooding Attack]], and others.
- The policies themselves and the routes sent between routers can be manipulated, which can lead to redirection of traffic causing huge denial of service attacks.

---
### Security Mechanisms

To protect BGP, there are several techniques that have been implemented and should be followed.

The announcements made by routers should be **authenticated**.
- This can be done by using hashes and [[Digital Signatures]].
- Using **IPsec**, which encrypts the entire [[IP]] packet, protecting against attacks like source IP address spoofing.

Utilizing a mechanism known as **PKI (Public Key Infrastructure)** that maps routes with Autonomous Systems(AS) using [[Certificates]].
- This validates that an announcement made by a router in an AS is actually owned by that AS.
- Prevents the propagation of invalid routes, which can be checked against publicly available records that state which AS has access to which routers and [[IP]] address blocks.

Routers can also be configured to only accepts certain routers and certain network prefixes. This is known as **route filtering**.
- This limits the potential for malicious router announcements.
- This needs regular updates to ensure that the network is properly connected and managed.

##### Path Validation Protocols

The previous defense mechanisms aren't enough to protect against attacks on BGP.
- **PKI** only checks that the AS announcing the route has the authority to do so. 
- It does not check the validity of the route itself, or the path that the route has taken.

> The importance of verifying the path taken by a route lies in ensuring that the routing announcement has not been hijacked or malformed.

This protects against attacks where attackers can insert or manipulate ASs in the route being announced, hence altering traffic flow.

**soBGP (Secure Origin BGP)** is one of those path validation protocols, and it simply ensures that the path announced actually exists and is valid.
- ASs jointly put their network topologies and connections in databases that are checked.
**S-BGP (Secure BGP)** is another protocol, where each AS on the path adds a layer of encryption by signing the route as it passes through it.
- This ensures that a route is authenticated by all the ASs it has been through.

> The deployment of these protocols is challenging and is not favored due to several reasons.

- There is a large complex overhead to actually implementing this protocols, as every AS on the path needs to perform some operation before forwarding the route.
- To deploy these protocols, cooperation and coordination is needed by large companies which is hard to achieve, as it might reduce the profits made, and cause customers to have to pay more.

---
