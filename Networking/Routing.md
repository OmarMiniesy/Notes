
### General Notes

Routers are devices connected to different networks.
- They can forward [[IP]] datagrams between networks.
- Forwarding is done through routing [[Protocol]]s.

Routers try to find the best path to send packets. They then forward the packets through one of its interfaces.

---
### Routing Protocols

These are [[Protocol]]s through which the routes are created and modified. These protocols are what are used to fill up the Routing Table.

---
### Routing Table

To choose which interface to route through, routers use the routing table.
- The routing table contains [[IP]] - Interface binds.

`0.0.0.0` is the Default Address, which is used when a packet is received with an unknown network destination.

> To ensure the best path is selected, paths are also assigned a metric. This metric is defined based on congestion and bandwidth.

Routing tables are found on routers and on hosts.

* To print the route tables: 
```
ip route //linux
route print // Windows
```

* To add a route to the routing table:
```bash
ip route add <ip>/<subnet> via <router-ip>
```

* To delete a route from the routing table:
```bash
ip route delete <ip>/<subnet>
```

To print the interfaces:
* `ifconfig` Linux

---
### Printing Routes For Packets

* To print the entire route of a packet through a network:
```bash
traceroute <dest-ip> //linux
tracert <dest-ip> //windows
```
> This uses [[ICMP]] messages, but sometimes some routers are configured to drop these requests, so this might not always work.

A better solution would be to try using the `ping` command but increasing the number of hops 1 by 1 until the destination [[IP]] is reached.

```bash
ping 8.8.8.8 -t 1
```
> The `-t` is the time to live flag, which is responsible for the number of hops.

---
