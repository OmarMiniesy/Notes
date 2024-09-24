
A collection of some of the commands I found useful and convenient to use. Check the [[Linux Privilege Escalation]] file for scripts focusing more on security.

> Checkout this [website](https://linux.die.net/abs-guide/index.html) for a guide to bash scripting.

### IP Address Manipulation 

- To change the [[IP]] address, subnet mask, and-or broadcast address of an interface:
```bash
ifconfig <int> <new-ip-addr> netmask <mask> broadcast <new-broadcast-addr>
```

- To change the [[Data Link Layer#MAC Address]] of an interface:
```bash
ifconfig <int> down
ifconfig <int> <hw> <ether> <new-mac-addr>
ifconfig <int> up
```

- To get an IP address from the [[Dynamic Host Configuration Protocol (DHCP)]] server for an interface:
```bash
dhclient <int>
```

---
### DNS Manipulation

- To add another [[Domain Name System (DNS)]] server:
```bash
echo "nameserver <ip-addr>" >> /etc/resolv.conf
```

> Check out also [[Virtual Hosting]].


---

