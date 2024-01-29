
### General Notes

> Also known as TCP/IP, or Internet [[Protocol]].
> It sends datagrams (packets) to the communicating nodes, and uses IP Addresses to identify hosts.
> Hosts are identified by unique IP Addresses.

Used in the [[Network Layer]] of the protocol stack.
The IP protocol has these properties:
1. It is a best effort delivery system, with no gaurantees.
2. Not responsible for a reliable transmission of packets.

> `ip addr` on Linux to view the IPs, [[Data Link Layer]] MAC addresses, and interfaces.

---
### IPV4 

> This is IP Version 4
> Uses 4 bytes separated by `.`
> The 4 bytes are also called octets
> Each octet can range from 0 - 255

##### Special IP Addresses
* `0.0.0.0 - 0.255.255.255` 
* `127.0.0.0 - 127.255.255.255` for Local Host
* `192.168.0.0 - 192.168.255.255` for private networks

##### Netmask (Subnet)
> Used to identify the network of the IP address.
> Subnet and IP address together get the exact host required.
>  The netmask can be represented as a number of consecutive ones.

##### Classful Addressing
* Class A : `0.0.0.0 - 127.255.255.255`
* Class B: `128.0.0.0 - 191.255.255.255`
* Class C: `192.0.0.0 - 223.255.255.255` 

#### CIDR (Classless Addressing)
> To get the network IP address, simply AND the IP address with the netmask.
> After the AND, the IP address is the network prefix.
> The network prefix can be represented as `xx.xx.xx.xx/<ones>`
> The remaining part of the IP address, or the host address, can be deduced by ANDing with inverse of the subnet.

> The inverse of the netmask tells us the number of hosts this network can contain
> If the inverse has x bits, then the network can contain $2^x$ different hosts.

##### Special Addresses From CIDR
* The host part is all 0's, this is the network address
* The host part is all 1's. this is the broadcast address

> Therefore, total number of available hosts is $2^{x}- 2$.

---
### IPV6 

> This is IP Version 6
> Uses 8 16 bit hex numbers separated by `:`
> Total 128 bits. First 64 are network, last 64 are device
> The first 64 ends with 16 bits to indicate subnet

##### Special Addresses

* `::1/128` Loopback address
* `::FFFF:0:0/96` IPV4 mapped addresses

---

