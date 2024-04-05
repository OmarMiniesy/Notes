
### General Notes

> Application layer support [[Protocol]].
> Converts URLs to [[IP]] addresses, these URLs are called DNS names. **Name Resolution.**

> Browsers look up records found in the `/etc/hosts` file before requests are sent to the DNS server.

> Misconfiguration of DNS servers allows for the [[Zone Transfers]] attack.

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
