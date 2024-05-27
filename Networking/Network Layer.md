### General Notes

The [[IP]] address is used in the network layer of the protocol stack. It has several functions:
* It performs [[Networking/Routing|Routing]].
* Passes the packets to the [[Transport Layer]].
* Performs error detection and correction.

---
### Error Detection

Before transmission, there is first a check done such that no collision takes place. Packets immediately stop transmission whenever a collision is detected.
* After 46 bytes of transmission if no collision is detected, then the packet should be sent normally, and the recipient opens it.
* If collision is detected, then less than 46 bytes will have been transmitted. Recipients discard packets that are less than 46 bytes in size.

---
### Fragmentation

Sometimes, hardware does not allow for packets of large sizes to be sent. This is why fragmentation is used.

> The maximum size of the payload field in packets is called the `MTU`, or the Maximum Transmission Unit.
* This is usually 1500 bytes.

All senders must fragment their packets if they are larger than this `MTU`.

> Packets dont arrive in order at the destination. The recipient is responsible for recollecting and building the packet from the fragments.

The recipient uses the `fragment offset` and a `flag` in the [[IP]] packet headers to recreate the packets again.
* The offset is calculated using the destination in bytes.
* The flag is used to determine if it is the last fragment. 
	* If it is 1, then it isnt the last fragment. 
	* If it is 0 and there is an offset, then it is the last fragment. 
	* If it is 0 and there is no offset, then there is only 1 packet with no fragments.

> Missing fragments cause their packets to be dropped.

---
