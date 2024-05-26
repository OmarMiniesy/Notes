
### General Notes

Application layer support [[Protocol]].
- Converts URLs to [[IP]] addresses by sending requests to the DNS server.
- These URLs are called DNS names, and a process called **Name Resolution** takes place.

> Browsers look up records found in the `/etc/hosts` file before requests are sent to the DNS server.

Uses UDP [[Protocol]] and [[Port]] number 53.

Misconfiguration of DNS servers allows for the [[Zone Transfers Attack]].
###### DNS Configuration
Local DNS server information is found in `/etc/resolv.conf`.
- Changes made to this file can be removed.
- Change the `/etc/resolvconf/resolv.conf.d/head` file to ensure persistent changes in `/etc/resolv.conf`.
- Run the `sudo resolvconf -u` command to update the contents in the file.

---
### DNS Records

The information present in the different records found in DNS databases:

| Name  | Description                                          |
| ----- | ---------------------------------------------------- |
| A     | Regular mapping between hostnames and IPV4 address.  |
| PTR   | Mapping between IPV4 address and hostname.           |
| CNAME | Creates an alias for a domain.                       |
| TXT   | Stores text information.                             |
| MX    | Routes emails to the correct email recieving server. |
| NS    | Nameserver for a domain.                             |
| SOA   | The primary name server for a domain.                |

[Resource](https://www.tutorialspoint.com/dns-resource-records).

---
### DNS Hierarchy

The domains are organized in a hierarchical structure.
- Each domain name can be structured as a tree, with a max tree length of 128.
- There are no name collisions.

There are different server levels in the hierarchy:
1. **Root**: Top of the DNS hierarchy, and there are 13 of them labeled A through M, `a.root-servers.net` to `m.root-servers.net`. They direct queries to the TLDs.
	- The root server [[IP]]s can be viewed in the `/etc/bind/names.conf/default-zones` file.
2. **Top Level Domain (TLD)**: One level below the Root servers. They manage the TLDs like `.com`, `.edu`, `.org`, and so on. Each TLD of these has its own set of servers managed by the Internet Corporation for Assigned Names and Numbers (ICANN).
3. **Second Level Domain (SLD)**: Servers that are one level below the TLDs and are responsible for the next portion of the domain name, like `google` in `google.com`. These are registered by companies or individuals, and configure the **authoritative servers** for this domain.
4. **Subdomains**: Beyond the SLDs, organizations can create multiple sublevels like `www.google.com`. Management and configuration of these levels are typically handled by the organization that owns the domain and its DNS records.
5. **Hosts**.

> Each server in the hierarchy is responsible for its zone, and has the address of the root servers.

There are different **Zones** found in this hierarchy. A DNS zone is an administrative part of the namespace that is managed by a certain organization, called the **administrator**.
- A large domain can be divided and stored in many zones.
- This also goes for any subdomains for any of these domains. However, sometimes subdomains can be added to different zones.
- A zone has DNS records related to the subdomains and domains that it contains.
- The **authoritative name servers** are responsible for managing the DNS records for a zone by answering to queries aimed at this zone.
- Each Zone has its own name server, but a name server can have many Zones.

> The administrator of the zone is responsible for maintaining the DNS records as well configuring the Zone Transfers, which is how DNS information moves from one server to another.

#### Authoritative Name Servers

This server has access to all the records for a **DNS Zone**.
- It is the server that is configured to answer any DNS requests for its zone without referring to another server.

> It is the final reference for a query. When a query for a domain name reaches an authoritative name server, the server provides the *final answer*.

---
### Name Resolution

Performed by **recursive resolvers**: servers that contact TLD servers and follow the structure to resolve the name of the host.
- Resolvers are DNS servers provided by ISP or are publicly available.
- Also known as the local DNS server.

1. **Initial Query**: When a user types a web address into a browser, the query first goes to a recursive resolver (typically provided by the user’s ISP or a third-party DNS service). The resolver's job is to find the IP address associated with the domain name.
2. **Contacting Root and TLD Servers**: The recursive resolver first queries a root DNS server, which directs it to the appropriate Top-Level Domain (TLD) server for the domain’s suffix (e.g., `.com`, `.net`).
3. **Querying the Authoritative Server**: The TLD server provides the addresses of the authoritative name servers for the specific domain being queried. The recursive resolver then contacts one of these authoritative servers to get the specific records for the domain.
4. **Response to User**: Once the authoritative name server provides the required records (like the A record for the domain), the recursive resolver sends this information back to the user’s device, allowing the browser to connect to the correct IP address.

> IP address of root servers are hardcoded in configuration of resolver.

This operation can be reversed, to get the DNS from the IP. 
- `Ping` utility in Linux does this.

#### Caching and Propagation

**Caching** is fundamental in DNS because it enhances the efficiency and speed of the internet by reducing the load on DNS servers and decreasing the latency for users. 
- This caching is done for positive as well as negative responses for queries.
- Caching is done in many places: The resolver, the browser, and the DNS servers.
- Cached entries have a TTL, time to live, after which they are removed.

**Propagation** is the process by which updates to DNS records spread throughout the entire internet's DNS infrastructure. This process involves updating and distributing the new DNS information across all servers that may cache DNS data.
- The updates for a record are not seen until their old counterparts are removed from the cache. Therefore, the smaller the TTL, the smaller the propagation delay.

---
### Tools

###### `nslookup`

Used to get information about IP addresses or domain names.
```
nslookup tesla.com
```
- Returns information stored in DNS records.

To query for the different record types as stated above, use the `-query` flag.
```
nslookup -query=<TYPE> <domain> <server>
```
- `<TYPE>` can be `A`, `PTR`, `MX`, `TXT`, ...
- Can use `-query=<>` or `-type=<>` interchangeably. 

###### `dig`

Same as `nslookup` but returns more information.
```
dig tesla.com @<server>
```
- Can specify which server to obtain data from.
- Server can either be name or IP, such as `1.1.1.1`.

To query for different types of records, simply add it to the command.
```
dig <TYPE> tesla.com 
```
- `<TYPE>` can be `a`, `mx`, `x` instead of `ptr`, `txt`, ...

---
