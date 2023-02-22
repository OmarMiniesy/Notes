
### General Notes

> Routers are devices connected to different networks.
> They can forward [[IP]] datagrams between networks
> Forwarding is done through routing [[Protocol]]s

> Routers try to find the best path to send packets
> They then forward the packets through one of its interfaces

---

### Routing Table

> To choose which interface to route through, routers use the routing table.
> The routing table contains IP - Interface binds

> `0.0.0.0` is the Default Address, which is used when a packet is recieved with an unkown network destination

> To ensure the best path is selected, paths are also assigned a metric. This metric is defined based on congestion and bandwidth

> Routing tables are found on routers and on hosts.
> To print the route tables: 
* `ip route` or `route` Linux
* `route print` Windows

> To print the interfaces:
* `ifconfig` Linux

---

### Other Commands

> Add a route to the route table ` ip route add <ip>/<subnet> via <router-ip>`
