
### General Notes

[[Protocol]] used to determine the [[Data Link Layer]] MAC address, given the [[IP]] address of the host.

> It was initially used to map the address of one protocol to the address of another protocol.

---
### [[Protocol]] Details

There are two main messages being, the ARP reply and the ARP request.

> The host initiating the connection sends a request, and the host that should recieve the message sends a reply back to the initiator.
###### ARP Request From Sender
Sent using broadcast to the entire network with these header fields:
* SRC IP: Sender IP.
* SRC MAC: Sender MAC.
* DST IP: RECIPIENT IP.
* DST MAC: `00:00:00:00:00:00`.

This packet is recieved by everyone on the network. Only the host that communication is intended with replies.
###### ARP Reply From Recipient
Sent using unicast to the initiator.
* SRC IP: Recipient IP.
* SRC MAC: Recipient MAC.
* DST IP: Sender IP.
* DST MAC: Sender MAC.

This data is then stored in the ARP cache of the sending host. 

---
### ARP Cache

Table that stores the data from the ARP protocol. It maps [[Data Link Layer]] MAC address to [[IP]] address.

This table's data is refreshed, so the ARP protocol is used again to fill it up.

> To view the ARP Cache
* `arp -a` Windows
* `ip neighbour` Linux

> To delete an entry in the table:
```bash
sudo arp -d <IP>
```

---
