### General Notes

This is a way of targeting the availability of a service, i.e. taking it down. 
- This can be done by exhausting the resources of a server, so no more connections can be made, denying users access to the service.
- This attack usually concerns targeting the critical point of a system, or the part that has the least amount of resources available to bring it all down - the **bottleneck**.

> It is an attack that causes a machine to be unavailable, and not able to perform its basic functionality.

There are several ways of performing such attacks, but most utilize techniques that can circumvent defenses such as [[Firewall]]s by spoofing [[IP]] addresses to bypass filters if any exist.

---
### Distributed Denial of Service (DDOS)

This flavor of DOS doesn't originate from a single attacker machine, but a coordinated effort between multiple machines.
- This can be achieved by using botnets [[Malware]].

---
### Amplification Attack

This is a form of DOS that abuses the difference in size between request and response packets.
- This is evident through [[Domain Name System (DNS)]] ,where sending a small request asking for a domain name, is replied to with much larger and bigger response data.

This can be abused where an attacker can spoof a DNS request to act as if it came from the victim machine, and the DNS responses will be directed back to the victim.
- The victim machine starts to receive a large number of packets that can reduce the performance of the machine.

> Note that this attack can work because it uses UDP [[Transport Layer]], meaning that no connection needs to be established.

##### Advantages

- The attacker identity remains hidden.
- The attack can overwhelm the victim machine with a large amount of bandwidth, while only using a small portion of their own bandwidth.

##### Disadvantages

 - Will not work over TCP [[Transport Layer]], as there needs to be a connection established.
- This requires that the attacker can guess the [[IP]] address of the victim machine with no prior knowledge.
	- Even if the attacker can guess the [[IP]], ISPs can prevent packets that originate from a source IP that isn't from the ISP itself using **egress filtering**. The ISP will check if the IP in the packet belongs to the network it is in, if that isn't the case, the packet can be dropped.

---
