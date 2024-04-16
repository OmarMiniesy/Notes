### General Notes

A network [Protocol](Protocol.md) used to automate the process of [IP](IP.md) address configuration.
- Also used to assign default gateways, [Domain Name System (DNS)](Domain%20Name%20System%20(DNS).md) servers, and other services.

> Replacement of old protocol BOOTP, and it is an *application layer* protocol.

The configuration information handed out by the server is called the **DHCP Options** and it includes:
- Subnet mask.
- Router.
- Domain Name Server.
- Hostname.
- Domain name.

> Uses [[Port]] 67 for the server, and 68 for the client.

---
### DORA - Protocol Steps

A device that joins a network doesn't have an [[IP]] address, so its first message is broadcast to the entire network.
- Sometimes, there is a static IP address to be used by default.

1. **Discover**: This is the broadcast message with IP `255.255.255.255` as destination. This shows that the client is in need of IPv4 configuration.
2. **Offer**: The server responds with an offer message that is unicast to the client only. Contains *proposed* information for the new [[IP]] address and other configurations. 
3. **Request**: The client answers the proposal, requesting the information from the DHCP server. This message is also a broadcast, to make sure that if there are multiple servers, they all know which server is chosen.
4. **ACK**: The server acknowledges the request with a unicast message to the client.

---


