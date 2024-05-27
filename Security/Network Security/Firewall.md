
### General Notes

Software module running on a computer or network device.
- They filter packets coming in and out of a network based on security policies and access control lists.

> Can be used to perform Network Address Translation (NAT) and [[IP]] masquerading

There are different types of firewalls for the different layers of the network stack.
- Stateful and Stateless firewalls for the [[Network Layer]].
- [[Transport Layer]] firewalls.
- Application Layer firewalls. These are proxy firewalls.
- Next Generation firewalls.

---
### Stateless Firewall 

Administrator can create rules which can filter packets according to characteristics.
* Source [[IP]]
* Destination [[IP]]
* [[Protocol]]
* Source [[Port]]
* Destination [[Port]]

Packet filters inspect the header of the packet and take action.
* **Allow** a packet to pass.
* **Drop** a packet without notifying source host.
* **Deny** a packet and notify source host.

> This firewall can only inspect single packets, with no state being kept. There is no history or memory being kept. 

---
### Stateful Firewall

This firewall checks packets against set access control policies.
- If the policies allow the packet to pass, the firewall forwards the packet to its destination.
- Otherwise, the packet is dropped.
- The access list rules are processed one by one in order until a match is found.

These firewalls maintain state, that is it keeps track of all open connections that have been established.
- Keeps tracks of the IP addresses used, the port numbers used, and the sequence numbers.
- if the packet is within an allowed connection, it is forwarded.
- Moreover, to ensure proper memory handling, connections that are inactive are timed out and removed.

> By keeping state, packets can be checked with their connection for more security. Moreover, some data in the packets can be inspected.

If the packets are not part of an active connection, they are checked against the given access control rules.
- If it passes these rules, it is forwarded, and a connection can be opened.

---
### Application Layer Firewall

Check all the OSI layers.
- Check also the payload of the packet, not just the header.

> This firewall acts as a proxy to do so.

---
