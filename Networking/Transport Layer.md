
### General Notes

> Serves as the communication channel for processes in the Application Layer.
> Transmission Control [[Protocol]] (TCP) and User Datagram [[Protocol]] (UDP).

> The transport layer uses [[Ports]] to identify the processes running on the machines that use this communication channel to send and recieve data.

---

### TCP

> Famously used in TCP/[[IP]], used by the internet.
> Used by email clients, web browsers, and FTP clients

>TCP garauntees packet delivery.
>TCP is connection oriented: must establish a connection before transferring the data


##### TCP Three Way Handshake

> In the header fields of the packets, the Sequence number, Acknowledgement number, and SYN and ACK flags are needed for the handshake.
> What happens is that the 2 devices connecting need to synchronize their Sequence and Acknowledgement numbers.

> SYN Packet
1. Client sends TCP packet to server with SYN flag enabled and random Sequence number. 

> SYN/ACK Packet
2. Server replies with a packet with both SYN and ACK flags enabled, a random Sequence number, and the Acknowledgement number as an increment of the previous Sequence sent by client.

> ACK Packet
4. Client completes handshake by sending a packet with Acknowledgement flag enabled. The sequence number is the same as previous Acknowledgement number, and Acknowledgement number is an increment of previous Sequence number sent by server.

#### [[Firewall]] or IDS Stopping the Handshake

>  SYN is sent, but no SYN/ACK replied
>  SYN is sent, but RST/ACK replied
>  This can be used to detect the presence of a firewall or another device

---

### UDP

> UDP is faster than TCP, and it provies a better **throughput** (number of packets per second).
> Used by multimedia apps that can tolerate loss of packets.

> UDP is simpler than TCP
> Doesn't garauntee packet delivery
> Connectionless.

---
