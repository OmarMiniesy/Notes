### General Notes

Traffic tunneling is an encapsulation process where traffic of one type of [[Protocol]] is encapsulated inside another type of traffic.
- This is used to hide the data and to bypass restrictions.
- Encapsulation takes place inside common, everyday protocols, like [[ICMP]] or [[Domain Name System (DNS)]].

##### ICMP Tunneling

ICMP is mainly used for diagnosing network communication issues and testing.
- However, it is also used by attackers to conduct [[Denial of Service (DOS)]] attacks, data exfiltration, and for Command and Control activities.
- Since ICMP packets can carry a data payload, this can be used to carry data for various reasons and various protocols like [[HTTP]], TCP, or [[Secure Shell Protocol (SSH)]] data.

Indicators of ICMP tunneling:
- Large volume of ICMP traffic.
- Weird packet sizes. (default of 64 bytes)

##### DNS Tunneling

DNS is used to resolve [[IP]] addresses, and is commonly trusted.
- However, if an adversary creates a domain address and configures it as a C2 server, malware can be configured to communicate with it for whatever reason.
- The queries sent by the malware are usually longer than the default size and are sent to subdomain addresses of that domain. The subdomains can sometimes be the encoded commands.

Indicators of DNS tunneling:
- Long query length.
- Weird subdomain and domain names & length.
- Long addresses that might seem encodings.
- Statistical analysis of the volume of DNS requests for a target.
- Known tools like `dnscat` or `dns2tcp`.

---
### Using [[Wireshark]]

##### ICMP Tunneling

To view ICMP traffic, use the `icmp` filter.
- To check for packets with large sizes (anomalies), try filtering for packet size larger than the default of 64 bytes:
```wireshark
icmp && data.len > 64
```

##### DNS Tunneling

To view DNS traffic, use the `dns` filter.
- To check for queries with large domain names:
```wireshark
dns.qry.name.len > 15
```

---
