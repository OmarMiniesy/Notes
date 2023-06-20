
### General Notes

> Application layer [[Protocol]]
> Converts URLs to [[IP]] addresses, these URLs are called DNS names. **Name Resolution.**
> It is a support protocol

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

> IP address of root server are hardcoded in configuration of resolver

> This operation can be reversed, to get the DNS from the IP. 
> `Ping` utility in linux does this.

---

### `nslookup`

> tool that translates hostnames to [[IP]] addresses.

---
