
### General Notes

This attack abuses the existence of the half open connection queue that is created during the [[Transport Layer]] TCP [[Protocol]] 3 way handshake.

> Check my SEED Labs Solution.

---
### Methodology and Attack

> To ensure this attack works, we first need to make sure that the server does not have SYN cookies enabled, as this is the countermeasure to this attack.
```bash
sudo sysctl -w net.ipv4.tcp_syncookies=0
```

The main idea is that when a client wants to talk to a server, the 3 way handshake is started. The first packet sent from the client, the SYN packet, is stored into the half open connections queue at the server.
* This queue is not that long, which creates a bottleneck.
* **This queue is [[Port]] specific.**

> The main goal for the attacker is to fill up this queue, preventing new connections from being opened at this port at the server side for a specific [[Port]].

However, if the attacker simply sends packets from his [[IP]], then the [[Firewall]]s can pick this up and place a filtering rule. Moreover, this can also hurt the attacker machine as the server is still trying to connect with that machine.

> Hence, the attacker sends packets from random [[IP]]s quickly, bombarding the server with requests.

This can be done by using the `netwox` tool:
```bash
sudo netwox 76 -i <ip> -p <port>
```
- The `76` is the number of the SYN flood attack in the tool.
- Enter the IP and PORT numbers for the victim machine.

Once that is complete, the server's network connections can be observed using the command:
```bash
netstat -nat
```
* This shows that there are a lot of TCP connections that are in the `SYN_RECV` state, waiting for the completion of the handshake.
* Trying to open a new connection to that port will be very slow, and might not work.

---
### Counter Measures

##### RST Packets

In order to clean up the half open connection queue, the server is still trying to complete the handshake with all of the [[IP]]s that sent the SYN packets.
* Server sends SYN+ACK packet to the sending client.
* The client sees this message, but the client never initiated a request.
* The client sends a RST packet to the server.
* The server removes the SYN packet from its queue.

> Since the IPs the attacker sends from aren't actual IPs that wanted to start a connection, they send the server a RST packet to stop the handshake. This then clears up the queue one by one.

Therefore, for the attack to be successful, the rate in which the attacker sends the SYN packets must be faster than the rate in which the clients send back the RESET packet and pop it from the queue.

##### SYN Cookies

Its idea is to discard the usage of the half open connection queue.

> The cookie encodes information from the SYN packet that came, and sends it with the next packet in the handshake, instead of storing it in the queue.

This discards using the queue, and stores all information in the packet. This removes the need for the queue, which renders the attack useless.

---
