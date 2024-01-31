
### General Notes

> Serves as the communication channel for processes in the Application Layer.
> Transmission Control [[Protocol]] (TCP) and User Datagram [[Protocol]] (UDP).

> The transport layer uses [[Port]]s to identify the processes running on the machines that use this communication channel to send and recieve data.

---
## TCP

> Famously used in TCP/[[IP]], used by the internet.
> Used by email clients, web browsers, and FTP clients
#### Properties

>TCP garauntees packet delivery since it is connection oriented. 
* must establish a connection before transferring the data.

This somehow emulates some sort of virtual buffer, with the client buffer on one side, and the server buffer on the other side. Any data that is sent gets sent to these buffers, and then TCP decides when and how to send the data. 

> The TCP buffer is cient specific. So if two different clients send to the server, the server can differentiate between their packets. This buffer is also application specific. So there is a unique buffer for every pair of [[Port]] and [[IP]] combination.

For a single client, since the packets are sent in the buffer, all packets are merged together. There is no boundary implemented by default that says how many bytes are present by default. Applications place such boundary while sending packets to be able to differentiate between the packets.

> TCP maintains order of packets being sent, even though [[Network Layer]] doesn't gaurantee in order delivery.
* This is done through the sequence numbers, a header field in the packets.

#### Three Way Handshake

In the header fields of the packets, the Sequence number, Acknowledgement number, and SYN and ACK flags are needed for the handshake.
* The goal is for the devices communicating to synchronize these numbers.

> SYN Packet
1. Client sends TCP packet to server with SYN flag enabled and random Sequence number. 

> SYN/ACK Packet
2. Server replies with a packet with both SYN and ACK flags enabled, a random Sequence number, and the Acknowledgement number as an increment of the previous Sequence sent by client.

> ACK Packet
4. Client completes handshake by sending a packet with Acknowledgement flag enabled. The sequence number is the same as previous Acknowledgement number, and Acknowledgement number is an increment of previous Sequence number sent by server.

When a SYN packet gets sent in the first step, the server stores this source [[IP]] address in a queue. This queue holds all the half-open connections, and the entires get popped once the handshake is complete. The queue size is not large, but it is unique per [[Port]].
> This was the motivation for the [[SYN Flooding Attack]].

#### [[Firewall]] or IDS Stopping the Handshake

>  This can be used to detect the presence of a firewall or another device.
* SYN is sent, but no SYN/ACK replied.
* SYN is sent, but RST/ACK replied.

#### Closing Connections

###### 1. Gracious Method
The FIN and ACK flags, and the sequence numbers are used to close established connections.

> FIN Packet
1. Client wants to close connection with the other client, so the client sends a FIN packet with a sequence number.

> ACK Packet
2. The other client responds with an ACK packet, with the sequence number plus 1.

This however, only closes the connection in one direction between the clients. The other client must also repeat this process to close the connection from the other direction.

###### 2. Enforced Method
The RST flag and the sequence numbers are used to close connections forcefully.

> Only 1 packet is sent, the RST packet with a sequence number. There is no ACK packet sent in return.

This closes the connection from both directions, which gave rise to the Reset Attack, where an attacker sends a RST packet to one of the clients in a communication channel, impersonating the other client.
* The client that recieves the RST packet closes the connection.
* The other client, the one the attacker impersonates by using its [[IP]], is believed to have closed the connection.
* The SEQ numbers must match correctly at the client recieving the RST packet for it to be used.

---
### UDP

UDP is faster than TCP, and it provies a better **throughput** (number of packets per second). Used by multimedia apps that can tolerate loss of packets.

> UDP is simpler than TCP:
* Doesn't garauntee packet delivery.
* Connectionless.

Contrary to TCP, there is only one buffer at the server that listens from all clients. There are no different buffers for each client and application. Therefore:
* Each packet sent in the buffer has a boundary by default.
* The packets can have their senders differentiated.

>Hence, even though there is only 1 buffer, the packets can be differentiated and multiplexed based on the boundaries and source [[IP]]s.

---
