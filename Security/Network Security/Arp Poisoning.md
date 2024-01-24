
### General Notes

> Used to intercept traffic on a network.
> [[Address Resolution Protocol (ARP)]] packets are sent in the [[Data Link Layer]] to identify the MAC address.

> Hosts save these MAC addresses in ARP cache tables.
> Attackers want to manipulate data in this cache table.

> If attacker manages to change the data of the ARP tables of the two parties involved in a communication a Man in the Middle (MITM) attack is presented.

---
### ARP Simplicity

>ARP is **stateless**. 

This means replies dont have to be synced to a request sent before it. Any reply that is recieved by a machine updates the ARP cache of that machine, even if it didnt send a request for that [[IP]] address.

---

### Attack Techniques

There are three techniques to perform ARP cache poisoning. These might not all work in all scenarios.
##### 1. ARP Request
> For an ARP request, a host sends out an ARP request with its SRC-IP and SRC-MAC.
* This request is seen by other devices, so they update their ARP cache with this mapping.
* The target accepts the spoofed request, even if the ARP cache doesn't have an entry for that IP address.
##### 2. ARP Reply
> For an ARP reply, a host recieves information regardless whether it sent out a request or not with a SRC-IP and SRC-MAC.
* This reply is then used to update the ARP cache of the recipient host.
* The target doesn't accept the spoofed request if there is no entry in the ARP cache for that IP address.
##### 3. Gratuitous ARP Message
> Broadcasting a packet that has both SRC-IP and DST-IP the same, usually that of the host that should be acted as.
* This is sent to all devices on the network, and it convinces them that it is the machine with the IP it announces.
* The SRC-MAC is the MAC of the attacking machine, the one that will take on the role of the machine with the SRC-IP it is broadcasting.
* The target doesn't accept the spoofed request if there is no entry in the ARP cache for that IP address.

---

### Performing ARP Poisoning using `arpspoof`

> Enable [[IP]] forwarding. This garauntees that the machine forwards the packets intercepted to the real destination hosts.
```
echo 1 > /proc/sys/net/ipv4/ip_forward
```

> Intercepting data between two hosts using `arpspoof`.
```
arpspoof -i <interface> -t <target-ip> -r <host-ip>
```

> [[Wireshark]] can then be run to track and intercept the traffic.

---
