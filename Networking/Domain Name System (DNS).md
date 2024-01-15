
### General Notes

> Application layer support [[Protocol]].
> Converts URLs to [[IP]] addresses, these URLs are called DNS names. **Name Resolution.**

> Browsers look up records found in the `/etc/hosts` file before requests are sent to the DNS server.

---
### DNS Structure

* Top Level Domain (TLD)
* Domain part
* Subdomain part
* Host part

`www.sub.domain.com`
Host - sub domain - domain - TLD

---

### Name Resolution

> Performed by resolvers: servers that contact TLD servers and follow the structure to resolve the name of the host.
> Resolvers are DNS servers provided by ISP or publicly available.

1. Resolver contacts root name servers, contains info about TLDs
2. TLDs are asked about the domain
3. If there are subdomains, step 2 is repeated
4. Then the host name is requested.

> IP address of root server are hardcoded in configuration of resolver.

> This operation can be reversed, to get the DNS from the IP. 
> `Ping` utility in linux does this.

---

### DNS Records

The information present in the different records found in DNS databases:

| Name  | Description                                          |
| ----- | ---------------------------------------------------- |
| A     | Regular mapping between hostnames and IPV4 address.  |
| PTR   | Mapping between IPV4 address and hostname.           |
| CNAME | Creates an alias for a domain.                       |
| TXT   | Stores text information.                              |
| MX    | Routes emails to the correct email recieving server. |
| NS    | Name server for a domain.                             |
| SOA      | The primary name server for a domain.                                                     |

[Resource](https://www.tutorialspoint.com/dns-resource-records).

---

### Tools

###### Nslookup

> Used to get information about IP addresses or domain names.
> Returns information stored in DNS records.
```
nslookup tesla.com
```

To query for the different record types as stated above, use the `-query` flag.
```
nslookup -query=<TYPE> <domain> <server>
```
> `<TYPE>` can be `A`, `PTR`, `MX`, `TXT`, ...
> Can use `-query=<>` or `-type=<>` interchangeably. 

###### Dig

> Same as `nslookup` but returns more information.
> Can specify which server to obtain data from.
```
dig tesla.com @<server>
```
Server can either be name or IP, such as `1.1.1.1`.

To query for different types of records, simply add it to the command.
```
dig <TYPE> tesla.com 
```
> `<TYPE>` can be `a`, `mx`, `x` instead of `ptr`, `txt`, ...

---

### Zone Transfers

These are how secondary DNS servers recieve information from the primary DNS server, as well as any updates. Zone transfers copy a domain's database from primary server or secondary server to any unauthenticated other server/[[IP]] address.

> Using a master-slave architecture.
> The master DNS is sometimes misconfigured, but it should be configured to allow for zone transfers with restrictions.

> If an attacker can perform a zone transfer with the primary or secondary name servers for a domain, the attack can view all of the DNS records for that domain.

This [tool](https://hackertarget.com/zone-transfer/) gets DNS records of a target domain by testing using zone transfers.

To start the attack, we need to know the [[IP]] address of the DNS servers. Then, we can start to request for the domain of our choice from that server the copy of the zone transfer file, which has the record we need.

###### Identifying Name Servers and Primary Server

* Using `nslookup` to get the name servers, then the primary server using `type=soa`
```
nslookup -type=NS <domain>
```
* Using `dig`
```
dig ns <domain>
dig soa <domain>
```
* Using `host`
```
host -t ns <domain>
```

> After getting the address of the primary server, we can then use that to launch the zone transfer and obtain all the data.

###### Zone Transfer Attack

* Using `nslookup`
```
nslookup -query=axfr <domain> <server-ip>
```
> We can add `-type=<>` to output only certain DNS records after performing the zone transfer.

* Using `dig`
```
dig axfr <domain> @<server-ip> 
```
* Using `host`
```
host -t axfr <domain> <server-ip>
```

---
