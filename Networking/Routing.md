
### General Notes

Routers are devices connected to different networks.
- They can forward [[IP]] datagrams between networks.
- Forwarding is done through routing [[Protocol]]s.

Routers try to find the best path to send packets. They then forward the packets through one of its interfaces.

---
### Routing Protocols

These are [[Protocol]]s through which the routes are created and modified. These protocols are used to fill up the **Routing Table**. 

> An autonomous system(AS) is a very large network or group of networks that have the same routing policy. These are owned by Internet Service Providers (ISPs).

There is **internal gateway** routing and **external gateway** routing.
- Internal gateway routing is when packets are forwarded within the same network or autonomous system. These include `RIP`, `OSPF`, and others.
- External gateway routing is when packets are forwarded across different autonomous systems or networks. There is only 1 protocol, and it is `BGP`.

---
### Routing Policies

These are policies that are implemented by internet service providers within their autonomous systems to control the flow of traffic.
- Allows ISPs to accept or discard incoming traffic or outgoing traffic within its autonomous system from other systems.

> ASs have different sizes, and the different sizes buy connectivity to the internet from larger sizes. There are small and regional ASs.

The external gateway protocol `BGP` enforces some policies that allow for the connectivity of the autonomous systems of ISPs to ensure the internet remains connected, but also allows ISPs to create their own policies to produce revenue.

---
#### Border Gateway Protocol (BGP)

It is the main external gateway protocol. Communication using this protocol is done between routers that establish a TCP connection first. [[Transport Layer#TCP]].
- Routers send `keep alive` messages constantly every minute to keep the connection alive.

The main goal for this protocol is to allow connectivity between different networks on the internet. It does this through enforcing some rules, or *routing 
policies* that depend on relationships between the different ASs and ISPs.
###### Customer-Provider Relationship

- The customer here could be a small ISP, or an organization that needs network connectivity. 
- This customer will purchase routing information from the provider, and the provider is expected to connect the customer to larger ASs and customers from other providers.
- The customer will use BGP to announce the routes in its small network to the provider, which the provider then broadcasts to other ISPs and other providers.
- This means the provider is responsible for transferring data between its customers, and to other customers on different providers.

> This relationship is governed by money, meaning the customer pays for the provider's services. Contrarily, the peer to peer relationship is characterized by mutual exchange of information without monetary compensation.

###### Peer to Peer Relationship

- Allows large networks to exchange traffic between customers directly.
- There is no financial compensation, or *settlements*. It mainly happens when the traffic flow between the two ASs is large and roughly equivalent between them.
- Both parties benefit from direct access to each other's customers, without having to increase latency and pay for large bandwidth.
- ASs exchange routing information using BGP, but they only communicate information relating to their own customers, and not other ASs or peers.
- Peering isn't done by default between ASs, but instead, it is agreed upon in a process known as selective peering.

> Tier 1 ISPs form peers. Small competing ISPs form peers to save money.

Both of these relationships are important to consider for ISPs to make the most revenue. 
- Advertising the routes that bring them money is favorable.
- Not advertise routes that use its resources without benefitting their customers.
	- For instance, routers from other providers aren't announced by the provider because it encourages the customers on these providers to use its resources.

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
