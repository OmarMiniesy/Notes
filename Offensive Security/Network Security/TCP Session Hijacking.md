### General Notes

Two clients communicating using [[Transport Layer#TCP]] are in a session, which is controlled by:
* Source and Destination [[IP]]s.
* Source and Destination [[Port]]s.
* Sequence numbers.

These three conditions are what describe a TCP session. If an attacker can determine the necessary fields from these, an attacker can send data through that session. 
> The attacker is said to have hijacked the session.

> Check my SEED Labs [Solution](https://github.com/OmarMiniesy/Walkthroughs/blob/main/SEED%20Labs/Network%20Security/TCP%20Attacks%20Lab.md).

---
### Methodology

The attacker first needs to sniff the relevant fields that dictate the TCP connection's properties. 
* Gets the IP of one of the clients in the connection, and sends from it.
* Gets the IP of the other client in the connection, and sends to it.
* The source port is a random number, but it can be obtained from the sending client.
* The destination port needs to be obtained from the recipient client.
* The sequence number is obtained from a packet sent from the sending client.
* The acknowledgement number obtained from a packet sent from the sending client.

This can be done through [[Wireshark]], or other network sniffing tools assuming that the attacker is on the same LAN.

> The data we send will be appended at the recipient queue at the sequence number, hence, it is not necessary to use the exact next increment of the sequence number.

This means that the data we append will only show at the current sequence number we use. This is a characteristic of the queue and sliding window of TCP. If we use a sequence number that is within the sliding window, we are sure that this data will be sent, but will show only once its index is reached in the queue.
* If we use for example sequence number + 10, then after 10 bytes, our data will be printed or showed.

> Moreover, since the packets are added to the buffer (appended), the bytes are all concatenated together.

In order to achieve proper execution or correct data transmission, the data we want to send as attacker should be surrounded by characters that guarantee they are split from the remainder of the bytes.
```bash
\n <data> \n
```
* One solution is to use the `\n` new line character.

> While sending, we must set the ACK flag in the packet. This is to ensure that the data will be acknowledged by the recipient.
* The acknowledgement number we use should be 1 increment of the ACK number from the previous packet.

After correct incorporation of these numbers, the attacker can manage to send data to either one of the clients depending on which one it impersonates. However, this might break the existing connection.

---
### Aftermath

> After applying this attack, the initial connection will disconnect because the synchronization between them both has been disrupted.

This is the case because we set SEQ numbers as attackers and send it to one of the hosts. The sending host that is trying to send to the recipient client is still using an old sequence number. Once the sending host sends using the out-dated SEQ number, the recipient will not ACK this packet and discards it, since it is out of order.

> This is also the case with the recipient client, if it tries sending to the sending client. It will use an updated SEQ number that isn't the same expected number at the sending client, causing the packet to also not be ACK'd. 

Therefore, these two hosts will keep sending packets that will keep getting dropped, until the connection is terminated.

---
