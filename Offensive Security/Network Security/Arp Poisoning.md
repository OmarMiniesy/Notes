### General Notes

Used to intercept traffic on a network and conduct man in the middle attacks (MITM). 
- [[Address Resolution Protocol (ARP)]] packets are sent in the [[Data Link Layer]] to identify the MAC address.

Hosts save these MAC addresses in [[Address Resolution Protocol (ARP)#ARP Cache]] tables.
* Attackers want to manipulate data in this cache table.

> If attacker manages to change the data of the ARP tables of the two parties involved in a communication a Man in the Middle (MITM) attack can be presented.

Check My SEED Lab [Solution](https://github.com/OmarMiniesy/Walkthroughs/blob/main/SEED%20Labs/Network%20Security/ARP%20Cache%20Poisoning%20Attack%20Lab.md)

---
### Attack Techniques

There are three techniques to perform ARP cache poisoning. These might not all work in all scenarios.
##### 1. ARP Request
> For an ARP request, a host sends out an ARP request with its SRC-IP and SRC-MAC.
* This request is seen by other devices, so they update their ARP cache with this mapping.
* The target accepts the spoofed request, even if the ARP cache doesn't have an entry for that IP address.
##### 2. ARP Reply
> For an ARP reply, a host receives information regardless whether it sent out a request or not with a SRC-IP and SRC-MAC.
* This reply is then used to update the ARP cache of the recipient host.
* The target doesn't accept the spoofed reply if there is no entry in the ARP cache for that IP address.
##### 3. Gratuitous ARP Message
> Broadcasting a packet that has both SRC-IP and DST-IP the same, usually that of the host that should be acted as. It is a **reply packet** that is not a response to any request.
* This is sent to all devices on the network, and it convinces them that it is the machine with the IP it announces.
* The SRC-MAC is the MAC of the attacking machine, the one that will take on the role of the machine with the SRC-IP it is broadcasting.
* The target doesn't accept the spoofed request if there is no entry in the ARP cache for that IP address.

---
### Performing ARP Poisoning using `arpspoof`

> Enable [[IP]] forwarding. This guarantees that the machine forwards the packets intercepted to the real destination hosts.
```
echo 1 > /proc/sys/net/ipv4/ip_forward
```

> Intercepting data between two hosts using `arpspoof`.
```
arpspoof -i <interface> -t <target-ip> -r <host-ip>
```

> [[Wireshark]] can then be run to track and intercept the traffic.

---
### Man in the Middle Attack 

The attacker needs to be in the same local network of the two communicating hosts.

> To achieve the attack, both hosts need to have their ARP caches poisoned. They are convinced that the IP of the other host is mapped to the MAC of the attacker.

Packets received at the attacker have a different destination IP address than that of the attacker. The attacker machine has two scenarios:
* If attacker machine is configured as a router, it will relay the packet to the other host. This can be done by turning on IP forwarding.
* If attacker machine is not configured as a router, it will not relay the packet to the other host. To achieve that, we need to stop IP forwarding. This drops the packets.

```bash
sudo sysctl net.ipv4.ip_forward=0
```
- This turns off forwarding. Change to 1 to turn on.

> To achieve MITM attack, we need the second scenario. However, we need to add some configurations

Before the machine drops the packet, we need a copy of that packet to read it, and then we can manually send the packet to the other expecting host. 
* This way, we guarantee that the other host gets the packet from us, not from the real sending host.

---
### Defenses

1. **Static ARP Entries**: Manually configure ARP tables with static entries that map [[IP]] addresses to MAC addresses, which helps prevent unauthorized ARP replies.
2. **Use of Security Software**: Deploy network security tools and antivirus software that can detect and prevent ARP spoofing. (arpwatch)
3. **Network Segmentation**: Divide the network into smaller, manageable segments using VLANs. This limits the scope of ARP requests to smaller segments and makes it harder for an attacker to impact the entire network.
4. **Packet Filtering**: Configure switches and routers to block or filter out suspicious ARP packets. Some advanced switches can be set to allow ARP packets only from ports where ARP requests were originated.
5. **Monitoring and Alerts**: Regularly monitor network traffic for unusual ARP traffic and set up alerts for suspicious activities. This includes looking for multiple ARP requests/responses from the same IP or rapid changes in MAC addresses associated with an [[IP]].
6. **Switches**: Switches have MAC caches, which tracks [[IP]] address and MAC pairings. If a requesting device queries a MAC address that is in the switches table, it is sent directly.

---