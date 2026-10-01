### General Notes

Man in the middle attacks are when attackers secretly intercept communication between two parties and can alter the data or steal from it.

Some types of MITM attacks are:
- **Packet sniffing**: Capturing unencrypted data packets.
- **Session hijacking**: Stealing session tokens to impersonate users.
- **SSL stripping**: Downgrading [[HTTPS]] connections to [[HTTP]] to steal/alter data.
- **[[Domain Name System (DNS)]] Spoofing**: Redirecting legit traffic to fraudulent domains by manipulating DNS responses.
- **[[IP]] Spoofing**: Crafting malicious [[IP]] packets to impersonate systems.
- **ARP Spoofing**. Check out [[Arp Poisoning]] on how to perform this attack, and check out [[Detecting ARP Attacks]] on how to detect it.
- [[Attack Types#MITM Attacks|Wireless MITM Attacks]].

---
### Detecting ARP Spoofing

In summary, [[Address Resolution Protocol (ARP)]] spoofing is when an attacker sends fake ARP replies to trick devices into associating the attacker's *MAC* address with the legit [[IP]] address of a device.
- This allows the attacker to intercept, modify, and redirect traffic.

To detect this, we can look for:
- **Duplicate MAC-to-IP Mappings**: Multiple MAC addresses claiming the same IP address. Indicates impersonation.
- **Unsolicited ARP Replies**: High number of ARP replies without matching requests ("gratuitous ARP").
- **Abnormal ARP Traffic Volume:** A Large number of ARP packets in short intervals.
- **Unusual Traffic Routing**: Traffic rerouted through the attacker’s MAC.
- **Gateway Redirection Patterns:** Multiple destination MACs for the same gateway IP.
- **ARP Probe / Reply Loops**: Many ARP requests with `Who has 192.168.1.x? Tell 192.168.1.y` patterns.

##### [[Wireshark]] Filters

To look for all ARP requests:
```
arp.opcode == 1
```

To look for all ARP responses:
```
arp.opcode == 2
```

To look for gratuitous ARP replies:
```
arp.isgratuitous
```

To look at the ARP replies/responses for a specific host:
```
arp && arp.src.proto_ipv4 == X && eth.src == X
```

To look for duplicate IP to MAC mappings, we can use the following filter:
```
arp.duplicate-address-detected || arp.duplicate-address-frame
```

---
### Detecting [[Domain Name System (DNS)]] Spoofing

This is when an attacker intercepts a DNS query and sends a fake DNS response.
- The victim computer trusts the fake response and saves it in the DNS cache.
- The victim computer now connect to the [[IP]] sent by the attacker when they browse for the chosen domain.

To detect this, we can look for:
- **Multiple DNS responses for the same query**: A legitimate resolver and a forged responder reply to the same query. This is the single most reliable indicator.
- **DNS response from an unexpected source**: A DNS reply arrives from an IP address **that does not match any configured resolver** (like 8.8.8.8 or your DNS server).
- **Suspiciously short TTL (Time-To-Live) values**: Attackers use very low TTLs (1 - 30s) to keep poisoned entries short-lived and reassert control.
- **Unsolicited DNS responses**: A DNS reply appears without a corresponding DNS request from the victim.

##### Using [[Wireshark]]

To look for DNS responses from a certain DNS server's IP:
```
dns.flags.response == 1 && ip.src == X
```
- We can also negate the server IP to look for responses coming from other servers.

To look at the DNS traffic of a domain of interest:
```
dns && dns.qry.name == "X"
```

---
### Detecting SSL Stripping

This is when an attacker modifies traffic and removes [[Transport Layer Security (TLS)]] encryption between the client and the server.
- This causes the connection to be made using [[HTTP]] instead of [[HTTPS]].
- The attacker maintains a secure HTTPS connection with the server, while maintaining a plain HTTP with the victim.

This takes place using the following procedure:
1. **The victim initiates an HTTPS request** to a website.
2. **The attacker intercepts the request** using ARP spoofing or a rogue access point.
3. **The attacker connects to the website over HTTPS** but relays the response to the victim through HTTP.
4. **The victim unknowingly interacts over HTTP**, exposing sensitive data in plaintext.

To detect this:
- **Initial Request vs. Response:** The user's initial request may be for HTTPS ([[Port]] `443`), but the subsequent packets immediately shift to unencrypted HTTP ([[Port]] `80`) for the same domain.
- **Redirects/Link Rewriting**: Monitoring for redirects (HTTP Status Codes `301`, `302`) that persistently direct an HTTPS request to an HTTP resource.
- **[[Certificates]] Errors**: Although the attacker usually tries to hide this, the initial **TLS/SSL Handshake** may fail or display a self-signed certificate if the attacker uses a more direct proxying technique.

---
