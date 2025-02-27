### General Notes

This is a model that shows the importance of identifying Indicators of Compromise *IOCs* to cause disruptions for attackers and improve the cybersecurity posture of an organization.
- By utilizing [[Threat Intelligence]], organizations can target hard to change behaviors of attackers and improve their defensive measures.
- This model lays out the correct plan to properly utilize threat intelligence. 

---
### The Layers

The model is a hierarchical one, and it organizes IOCs and behaviors of attackers based on the difficulty the attackers are faced with once this adversarial data is detected/mitigated. The following layers are ordered from easiest to hardest to change for attackers:
1. Hash Values
2. [[IP]] Addresses
3. Domain Names
4. Network/Host Artifacts
5. Tools
6. TTPs ([[MITRE ATT&CK Framework]])

##### Hash Values - Trivial

The hashes of malicious files or codes can be computed and then used as signatures to be compared against.
- These hashes are used to uniquely identify a given malicious artifact.
- [Virus Total](https://www.virustotal.com/gui/home/upload) is a tool that is used to do hash lookups.

The reason this is easy for attackers to deal with is because the hash is computed uniquely for every bit in the file.
- Therefore, modifying the files, even by 1 bit, would produce a different hash.

> Fuzzy hashing can be used to perform similarity analysis between files with minor differences. Check out [SSDeep](https://ssdeep-project.github.io/ssdeep/index.html).

##### IP Address - Easy

An IP address can be blocked, or have the packets coming from it dropped using a [[Firewall]] if it is known.
- However, it is easy for attackers to circumvent this by simply obtaining a new IP address.
- This can be done by a tool like **Fast Flux**, which uses a [[Domain Name System (DNS)]] technique to hide attacks by associating multiple IP addresses to a single domain name through the use of bots and botnets.

##### Domain Names - Simple

Changing a domain is not as easy as it requires the attackers to purchase the domain, register it, and modify [[Domain Name System (DNS)]] records.
- However, there are providers that have [[Application Programming Interface (API)]]s that make it easy to do so.
- To detect malicious domains, proxy logs or web server logs can be used.

A way attackers can use domain names to perform attacks is by using characters that look like the real characters, but are in fact not real.
- This is called a *punycode* attack, and it is a way of converting words that cannot be written in ASCII to a Unicode ASCII encoding.

Another way to hide malicious domains is by using URL shorteners to hide the full domain name. The services that do that are:
- bit.ly
- goo.gl
- ow.ly
- s.id
- smarturl.it
- tiny.pl
- tinyurl.com
- x.co

> Adding a `+` at the end of the shortened URL will show the full URL.

##### Host Artifacts - Annoying

These include files or IOCs that are dropped by an attacker at the system being attacked.
- If these are detected, then they need to be changed, which can be time consuming.

##### Network Artifacts - Annoying

A network artifact, similar to a host artifact, takes time for the attacker to change.
- An example of a network artifact would be a *user agent*, C2 information, or a unique URI pattern.

Network artifacts can be obtained using tools like [[Wireshark]] and `Tshark`, or through the logs of an [[Intrusion Detection Systems (IDS)]].

##### Tools - Challenging

Tools if detected, would need the attacker to rethink their strategy.
- Tools are utilities that allow attackers to create malicious artifacts or perform malicious behaviors.
- They can be `.exe` files, `.dll` files, payloads, or crackers.

To detect tools, these techniques are used:
- File signatures used by antivirus software, check out [MalwareBazaar](https://bazaar.abuse.ch/).
- Detection rules, check out [Threat Detection Marketplace](https://tdm.socprime.com/)
- *YARA* rules.

##### TTPs - Tough

If the attacker's tactics, techniques, and procedures are detected and responded to, then the attacker would basically have to either come up with a new attacking plan, or abort mission.

---
