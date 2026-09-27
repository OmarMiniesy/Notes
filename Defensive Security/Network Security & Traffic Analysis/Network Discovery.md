### General Notes

Attackers when targeting a network, they first need to understand it.
- The process of understanding and discovering the target network is the first step an attacker.
- They want to understand the **Attack Surface**, or the assets that are open to the public accessible internet.

> Network discovery can also be done from an internal host, where an attacker is trying to pivot, or performing internal reconnaissance, this requires a deeper investigation. 

The type of information attackers are after when discovering a network:
- What assets do they have access to.
- What are the [[IP]] addresses, [[Port]]s, Operating Systems, and services running on these assets.
- The versions of the services running. (maybe something is vulnerable).

> Defenders should try to reduce the attack surface as much as possible.

Network Discovery can also be done in a benign manner:
- Blue team performing network discovery to understand their network
- Web crawlers and search engines can also try to map resources present.
- As such, a method is needed to differentiate between good and bad network discovery taking place.
	- An *allow-list* of known scanners (external or internal)
	- Utilize [[Cyber Threat Intelligence]] to flag scanning activities from known malicious sources.

> Check out [[Detecting Nmap Scans]] on how to detect network discovery.

---
### Types of Network Discovery

There are several types of network discovery events that can take place, depending on the phase of the attack, the type of the attack, and the goal of the attack.
- Check out [[Footprinting and Scanning]] for technical details on the types of scanning.
##### Horizonal Scanning

This is when the attacker performs a search for a singular open [[Port]] across multiple destination [[IP]]s.
- The attacker's goal here is to check which devices have this exact port enabled and functioning to be exploited.
- To identify this, we can filter for the same source [[IP]], same destination [[Port]], and multiple destination [[IP]]s.

##### Vertical Scanning

This is when the attacker performs a search on a singular destination [[IP]] for all the open [[Port]]s on it.
- This is used to footprint a single host and identify all of the exposed services.
- To identify this, we can filter for the same source [[IP]], same destination [[IP]], and multiple destination [[Port]]s.

---
