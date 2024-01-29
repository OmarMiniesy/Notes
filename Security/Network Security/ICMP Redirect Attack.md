
### General Notes

Uses the [[ICMP]] redirect message, and the attack is built primarily based on the [[Networking/Routing|Routing]] technology.

> There is no security involved in the ICMP redirect process, which can help create a Man In The Middle scenario.

This attack only works when the attacker is on the same LAN as the vulnerable machines, and we cannot redirect traffic to a router outside the local network.

---

### Methodology

The ICMP redirect basically informs another machine that there exists a better route to reach another destination.

However, hosts nowadays have a flag that automatically rejects these redirect messages due to their security concerns. Hence, we need on the vulnerable machines to make sure that `net.ipv4.conf.all.accepts_redirects=1`.

* To set as 1 if it is 0:
```bash
sudo sysctl net.ipv4.conf.all.accepts_redirects=1
```

Now, we can send these ICMP redirect messages.

> The [[ICMP]] redirect message is sent by routers, and is triggered whenever a router recieves a packet from a host, but with a condition: 
* The router knows a better route to reach the intended destination of that packet.

Therefore, we can abuse this, by sending *as attackers* to all machines in a network that we are the route that has the best cost. 
* The other machines recieve this redirect message, and update their routing tables.

> We need, as attackers, to impersonate a router for this attack to succeed. Hence, we set the source [[IP]] address to be that of a router's on the network. 

Since this is based on routing, the entries in the cache update frequently, so the attacker must constantly send these redirect messages.

> After recieving the packets, we then need to forward them to their actual destination so as not to raise alarm.

---
