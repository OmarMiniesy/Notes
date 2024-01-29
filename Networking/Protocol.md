
### General Notes

> Computers over networks talk via protocols
> Computers talk to exchange information in the form of packets.

---

### Packets

> Streams of bits running as electric signals
> These bits are then interpreted as data

> Packets are composed of 
1. Header : protocol specific structure that ensures the reciever can correctly handle the information in the payload.
2. Payload : contains the information

> Through information in header, nodes that are communicating can understand and use the packets.

##### Layers

> Different protocols are used for the different layers found in a network.
> These layers are defined by models, a famous one is the ISO/OSI model

1. Application
2. [[Transport Layer]]: This is where a cummincation channel is held between different hosts.
3. [[Network Layer]]: This is where [[IP]] addresses are used to identify hosts
4. [[Data Link Layer]]: This is where packet forwarding happens to identify the unique network card via the MAC Address
5. Physical

---

### Encapsulation

> The different layers use different protocols.
> The packets in each layer have different headers that are specific to the protocol.

> To solve this issue to be able to communicate between layers, we use encapsulation.
> The entire upper layer packet is the payload of the lower layer.

>TCP/[[IP]], a protocol, uses encapsulation.

> For each packet sent and recieved, encapsulation is applied, in different orders respectively.

---
