
### General Notes

> Used to intercept traffic on a network.
> Address Resolution [[Protocol]] (ARP) packets are sent in the [[Data Link Layer]] to identify the MAC address.

> Hosts save these MAC addresses in ARP cache tables.
> Attackers want to manipulate data in this cache table.

> Attacker manages to change the data of the ARP tables of the two parties involved in a communication, he can sniff the entire communication : Man in the Middle attack.

> Done through gratitous ARP replies.
> Telling the victim they can reach the machine's [[IP]] they want with a different MAC address, that of the attacker.

---

### Attack Procedure

> Attacker sends gratitous ARP replies: they are ARP reply messages without waiting for hosts to send ARP requests.
> This must be performed on all victims.

> To prevent data from ARP table from expiring, the gratitious replies are sent every small time quantum.

> Attacker also should forward the data to the required nodes as to not disrupt the communication.
> This does not mean the attacker can manipulate the data.

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
