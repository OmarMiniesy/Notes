### General Notes

Enterprise networks usually have a predetermined pattern to name users and hosts.
- This makes it easy to identify hosts/users by simply looking at the name.
- This also makes it easier for attackers to understand the pattern and start living in the network.

There are several protocols that ca be used to identify hosts and users based on network traffic analysis, like:
- [[Dynamic Host Configuration Protocol (DHCP)]] Traffic.
- [[Kerberos]] Traffic.
- NetBIOS Traffic.

---
### Using [[Wireshark]]

##### DHCP Analysis

To look for all *DHCP* traffic, can use the `dhcp` or `bootp` filter.
- To look for interesting events, we need to understand that each packet has its own data.

| Packet         | Information          | Wireshark Filter        |
| -------------- | -------------------- | ----------------------- |
| Request Packet | Hostname information | `dhcp.option.dhcp == 3` |
| ACK Packet     | Accepted Requests    | `dhcp.option.dhcp == 5` |
| NAK Packet     | Denied Requests      | `dhcp.option.dhcp == 6` |

For each of these packets, there are options inside that can be filtered for as well:
- A list of all possible options is [here](https://www.iana.org/assignments/bootp-dhcp-parameters/bootp-dhcp-parameters.xhtml).

| Packet       | Options                                                                                                                        | Filter                                       |
| ------------ | ------------------------------------------------------------------------------------------------------------------------------ | -------------------------------------------- |
| DHCP Request | Option 12: Hostname<br>Option 50: Requested IP Address<br>Option 51: Requested IP Lease time.<br>Option 61: Client MAC Address | `dhcp.options.hostname contains "keyword"`   |
| DHCP ACK     | Option 15: Domain Name<br>Option 51: Assigned IP Lease time.                                                                   | `dhcp.option.domain_name contains "keyword"` |
| DHCP NAK     | Option 56: Message details                                                                                                     |                                              |

##### NetBIOS Analysis

To look for all *NetBIOS* traffic, we can use the `nbns` filter.
- NetBIOS packets have a `Queries` section that showcase the query details, including the name, TTL, and [[IP]] address details.
- The `opcode` in the `Flags` section in the NetBIOS packet can be used to filter.

##### [[Kerberos]] Analysis

To look for all *Kerberos* traffic, we can use the `kerberos` filter.

| Kerberos Options | Description                                                  | Wireshark Filter                  |
| ---------------- | ------------------------------------------------------------ | --------------------------------- |
| `pvno`           | This is the protocol version                                 | `kerberos.pvno == 5`              |
| `realm`          | This is the domain of the generated ticket                   | `kerberos.realm contains ".org"`  |
| `sname`          | This is the service and domain name for the generated ticket | `kerberos.snamestring == "krbtg"` |
| `addresses`      | This is the client IP address and the NetBIOS name           |                                   |

---
