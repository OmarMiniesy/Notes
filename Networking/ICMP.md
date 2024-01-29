### General Notes

> Internet Control Message [[Protocol]].
> Famously used by the `ping` tool.

One of the protocols used by the [[Network Layer]] alongside the [[IP]].

---

### ICMP Messages

> The ICMP is used by the [[IP]] to send control messages and error messages.
* Control Messages: 
	* Echo request/reply : used to discover hosts.
	* Redirect : used to send a message to update the routing table.
	* Timestamp request/reply.
	* Router advertisement.
* Error Messages
	* Destination unreachable.
	* Time exceeded.

---
### ICMP Packet

The packet is characterized by the header fields, mainly the `type` and `code` headers. These headers are the ones used to distinguish between the different types of control and error messages.

| Message | type | code |
| ---- | ---- | ---- |
| Echo request | 8 | 0 |
| Echo reply | 0 | 0 |
| Time exceeded (TTL finished) | 11 | 0 |
| Time exceeded (fragment reassembly) | 11 | 1 |
| Destination Unreachable (network) | 3 | 0 |
| Destination Unreachable (host) | 3 | 1 |
| Destination Unreachable (protocol) | 3 | 2 |
| Destination Unreachable (port) | 3 | 3 |
| Destination Unreachable (fragmentation but no DF flag set.) | 3 | 4 |
| Redirect for network | 5 | 0 |
| Redirect for host | 5 | 1 |

---
