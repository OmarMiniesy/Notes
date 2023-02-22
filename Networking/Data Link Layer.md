
### General Notes

> Lowest layer of the [[IP]] stack
> This is where packet forwarding happens, also called **frames**
> Link Layer network address is called the **MAC Address**.
> Hubs and Switches are the devices in the local network that forward frames

---

### MAC Address

> Also known as the Media Access Control Address.
> They are unique for each network card. A computer may have multiple network cards.
> They are 6 bytes long, each byte represented in hexadecimal form. Each byte has 8 bits.
> The bytes are separated by `:`

> To view the MACs of the network cards: 
* `ipconfig /all` Windows
* `ip addr` Linux

#### Special MAC Address
* `FF:FF:FF:FF:FF:FF` Broadcast MAC address. 
>Packets are sent to all hosts in the local network if this is their destination address.

---

### Router Packet Forwarding

> To send a packet over a router between two different networks:

1. The packet has Source IP and MAC of the source computer 
2. The packet has Destination IP of the recipient computer
3. The packet has Destination MAC of the router
4. Once packet reaches the router, [[Routing]] occurs.
5. The router doesnt change source and destination IP
6. The router changes MAC source to that of router
7. The router changes MAC destination to that of recipient host.

---

### Switches

> Switches work with MAC address, and they need to keep a **forwarding table**, or Content Addressable Memory (CAM) table.
> Forwading table binds MAC to interface, and holds the **TTL**.

> Switches forward packets inside a local network through MAC addresses, and uses the CAM table to identify hosts with their MAC addresses.

##### CAM Table
> Stored in the RAM and is constantly refreshed
> TTL determines how long the entry will stay in the table, becasue table has finite size

---

### ARP (Address Resolution [[Protocol]] )

> When the IP address known, but the MAC isnt. 

The protocol is as follows: 
1. Host wants to send to recipient, knows only IP and not MAC.
2. Host builds ARP request containing IP of host and broadcast MAC address
3. Switch will forward this packet to all nodes on the network
4. Only the host with the correct IP address will reply back with an ARP Reply containing the MAC address of the recipient.

> ARP entries also have a TTL.
> The ARP is found in cache memory

> To view the ARP Cache
* `arp -a` Windows
* `ip neighbour` Linux
---
