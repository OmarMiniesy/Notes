### General Notes

OSINT threat intelligence tools are used to enrich an *IOC* during triage. They turn a bare indicator into context (reputation, ownership, age, behavior, related infrastructure) so the analyst can decide if it's malicious, benign, or needs deeper investigation.
- Each IOC type has its own questions and its own tools, so this note is split per IOC type. Each section starts with a **Methodology** to follow, then the **Tools** used for it.
- Sections follow the order of the [[Pyramid of Pain]]: file hashes, then [[IP]] addresses, domains, URLs, and certificates.
- Tools that cover several IOC types are described once in [[#Multi-IOC Platforms]] and referenced from the other sections.
- For what IOCs are and how CTI is produced, check out [[Cyber Threat Intelligence]]. For email IOCs (headers, sender, body), check out [[Phishing Analysis]].

> A clean reputation means "not known bad", not "known good". Always weigh the IOC against the alert context: the user, the host, the time, and what behavior is expected.

---
### File Hashes

##### Methodology

1. Look up the hash reputation.
	- How many engines flag it on [VirusTotal](https://www.virustotal.com/gui/home/search)? A few generic detections (`Generic`, `Heuristic`, `ML`) is weak evidence. Named family detections from several major vendors is strong evidence.
	- Do vendors agree on a family name? Use it to pull reports from [[#Abuse.ch|MalwareBazaar and ThreatFox]].
	- Is it signed by a trusted publisher, or a known legitimate binary? A legit binary running from an unusual path is still suspicious.
2. Check the file's history.
	- When was it *first seen*? A sample first seen right before your alert suggests a new or targeted sample.
	- What file names was it submitted as? Do they match the name on your host?
	- No results anywhere? Unknown is not clean. Custom or freshly compiled samples have no hits, so move on to analysis.
3. Review its behavior.
	- Check existing sandbox reports ([VirusTotal](https://www.virustotal.com/gui/home/search) *Behavior* tab, [Hybrid-Analysis](https://hybrid-analysis.com/)): processes spawned, files dropped, registry changes, network connections.
	- If there are none, run it in a sandbox ([[Dynamic Analysis]]) or analyze it with [[Static Analysis]].
4. Pivot on what the sample gives you.
	- Extract the contacted IPs, domains, and URLs, and investigate them using the sections below.
	- Find related samples using [[Static Analysis#Import Hashing (IMPHASH)|IMPHASH]], *ssdeep*, or [[YARA]] matches.
5. Scope it in your environment.
	- How many hosts have this hash, since when, and which process created it? One host versus hundreds changes the verdict.

> Search the hash, don't upload the file. Uploads to [VirusTotal](https://www.virustotal.com/gui/home/search) are shared with its paying subscribers, which can leak client documents and tip off an attacker who monitors VirusTotal for their own samples.

##### Tools

**[VirusTotal](https://www.virustotal.com/gui/home/upload)**
- Tool that does hash lookups and provides details about malware.
- Also accepts URLs, domains, and [[IP]]s. The *Relations* tab shows connected infrastructure (contacted IPs, passive DNS, dropped files), and the *Behavior* tab shows sandbox results.

**[Hybrid-Analysis](https://hybrid-analysis.com/)**
- This is a [[Malware]] behavior analysis website that gives information on network requests, [[Domain Name System (DNS)]], hosts, [[MITRE ATT&CK]] mapping, indicators, files, and processes, and more.
- Used for [[Dynamic Analysis]].

**MalwareBazaar, ThreatFox, YARAify** - [[#Abuse.ch]]

**YARA Tools** - [[YARA#Tools for YARA]]

---
### IP Addresses

##### Methodology

1. Classify the address first.
	- Is it private, loopback, or reserved ([[IP#Special IP Addresses]])? Then it's internal: investigate the host, not the IP's reputation.
	- Is it in a CDN or shared cloud range (Cloudflare, Akamai, CloudFront)? Thousands of unrelated sites share these IPs, so the IP's reputation tells you nothing. Pivot to the domain, URL, or *SNI* instead.
2. Check its reputation.
	- Is it reported on [AbuseIPDB](https://abuseipdb.com)? Which categories (brute force, scanning, phishing) and how recently? Do they match the alert?
	- Is it a known [[Command and Control|C2]] or botnet IP? Check [[#Abuse.ch|Feodo Tracker and ThreatFox]], and [VirusTotal](https://www.virustotal.com/gui/home/search).
	- Is it a mass internet scanner ([GreyNoise](https://viz.greynoise.io/))? Scanners hit every exposed host, so this is noise unless it targeted a vulnerable exposed service.
3. Check its location and anonymization.
	- Where is it located, and does that fit the alert? A US-based user is not expected to log in from Asia.
	- Is it a [[Virtual Private Network (VPN)|VPN]], proxy, or Tor exit node ([Spur](https://spur.us/), [IP2Proxy](https://www.ip2proxy.com/))? Attackers use these, and *residential proxies*, to appear close to the victim.
4. Check who owns it (ASN).
	- Which AS owns it, and of what type: residential ISP, hosting/cloud, business, education ([BGP.Tools](https://bgp.tools/), [ipinfo.io](https://ipinfo.io/))?
	- Does that fit the alert? Employees are not expected to log in from cloud hosting. Attacker infrastructure is usually on hosting providers, except for botnets and residential proxies.
5. Check what it exposes and hosts.
	- Which ports and services are open ([Shodan](https://www.shodan.io/), [Censys](https://search.censys.io/))? Look for exposed admin services and known C2 banners or default certificates.
	- Which domains resolved to it ([VirusTotal](https://www.virustotal.com/gui/home/search) *Relations*, [Robtex](https://www.robtex.com/))? Investigate them using [[#Domains]].
6. Scope it in your environment.
	- Which hosts talked to it, when, how much, and on which ports? Connections at regular intervals point to [[Detecting Beaconing Malware|beaconing]].

> Geolocation is approximate and can be spoofed with VPNs and residential proxies. A "local" IP proves nothing; the ASN type and anonymization checks carry more weight.

##### Tools

**[AbuseIPDB](https://abuseipdb.com)**
- Used to identify malicious [[IP]] addresses.

**[GreyNoise](https://viz.greynoise.io/)**
- Identifies [[IP]]s that mass-scan the internet, so internet background noise can be separated from targeted activity.

**[ipinfo.io](https://ipinfo.io/) and [iplocation](https://www.iplocation.net/)**
- Used to obtain the geolocation of an [[IP]] address.

**[BGP.Tools](https://bgp.tools/)**
- Used to obtain information about the **ASN** of an [[IP]] address.

**[IP2Proxy](https://www.ip2proxy.com/) and [Spur](https://spur.us/)**
- These are tools used to analyze [[Virtual Private Network (VPN)]], proxy, and Tor exit nodes.
- Useful to investigate whether this is a VPN node, or an actual legit IP address. Attackers can use these to fake locations to deceive analysts.

**[Shodan](https://www.shodan.io/) & [Censys.io](https://search.censys.io/)**
- Search engine that is used to obtain information on the [[Port]]s, services, and system configurations of hosts given their [[IP]]s.

**Feodo Tracker, ThreatFox** - [[#Abuse.ch]]

---
### Domains

##### Methodology

1. Inspect how it looks.
	- Does it imitate a known brand or your own org? Look for *typosquatting* (`micros0ft.com`), *combosquatting* (`microsoft-login.com`), a different TLD (`microsoft.co`), and *homoglyphs* (`rn` for `m`, Cyrillic `а`). Punycode domains start with `xn--`.
	- Does it look randomly generated (`x7kq2pzl.top`)? That suggests a *DGA*.
	- [dnstwist](https://github.com/elceef/dnstwist) generates lookalikes of a domain and checks which are registered.
2. Check its reputation.
	- Is it flagged on [VirusTotal](https://www.virustotal.com/gui/home/search), [[#Talos Intelligence|Talos]], or in previous [urlscan.io](https://urlscan.io/) scans? Is it listed on [[#Abuse.ch|URLhaus or ThreatFox]]?
	- What category is it given? *Newly registered*, *parked*, or *dynamic DNS* are signals on their own.
3. Check its age and registration.
	- When was it registered (`whois`/RDAP, check out [[Domain Name System (DNS)#Tools]])? [Unit 42](https://unit42.paloaltonetworks.com/newly-registered-domains-malicious-abuse-by-bad-actors/) defines newly registered domains as registered or changed owner in the last 32 days, and found over 70% of them malicious, suspicious, or NSFW.
	- Is it an old domain with a recent owner, registrar, or DNS change? It may be an expired domain re-registered by an attacker, or a compromised one.
	- WHOIS privacy alone isn't suspicious, since most registrations use it.
4. Check its DNS and infrastructure.
	- Resolve it and investigate the IPs using [[#IP Addresses]]. Many IPs rotating quickly with low TTLs suggests *fast flux*.
	- Check passive DNS history and which other domains share its IPs ([Robtex](https://www.robtex.com/), [VirusTotal](https://www.virustotal.com/gui/home/search) *Relations*).
	- Check certificate transparency for subdomains and sibling domains using [[#TLS Certificates]].
5. Scope it in your environment.
	- Who queried it (DNS and proxy logs), when was it first seen, and which process made the request?

##### Tools

**[Robtex](https://www.robtex.com/)**
- Searching for [[IP]] addresses and domains.

> Check out [[Domain Name System (DNS)#Tools]].

**URLhaus, ThreatFox** - [[#Abuse.ch]]

---
### URLs

##### Methodology

1. Never open it in your own browser.
	- Analyze it in a scanner or sandbox, and defang it when sharing (`hxxps://evil[.]com`).
2. Break it down.
	- Investigate the domain using [[#Domains]]. A legit domain with a malicious path usually means a *compromised site* or an abused service (file sharing, cloud storage, form builders).
	- Is it shortened or wrapped in a redirector (`bit.ly`, *Safe Links*, `?url=` parameters)? Expand it to its final destination.
	- Read the path and parameters: download extensions (`.zip`, `.iso`, `.js`, `.hta`), base64 blobs, or the victim's email address embedded in the URL (targeted phishing).
3. Check its reputation.
	- Is it listed on [[#Abuse.ch|URLhaus]] or flagged on [VirusTotal](https://www.virustotal.com/gui/home/search)? Has it been scanned before on [urlscan.io](https://urlscan.io/)?
4. Scan it and review the results.
	- Screenshot: does it impersonate a login page (Microsoft 365, a bank)?
	- Redirect chain: where does it end up? Every hop is an IOC.
	- Contacted IPs and domains, and downloaded files. Hash the files and investigate them using [[#File Hashes]].
5. Scope it in your environment.
	- Who received or clicked it (email and proxy logs)? Was anything submitted to it (`POST` requests) or downloaded from it?

> Phishing kits use *cloaking*: they serve benign content to scanners, unexpected countries, or unexpected user agents. A clean scan is not proof. Rescan from another country or user agent before closing.

##### Tools

**[Urlscan.io](https://urlscan.io/)**
- Automates browsing and crawling of websites to record activities and interactions.
- It provides information about the [[HTTP]] connections, the redirects present, any outgoing links, the [[Cookies]] and variables, as well as indicators ([[IP]]s, domains, and hashes) associated with the website.

**URLhaus** - [[#Abuse.ch]]

---
### TLS Certificates

##### Methodology

1. Check who issued it, and to whom.
	- Is it self-signed or issued by an unknown CA? Common on C2 servers and malware infrastructure.
	- Does the *subject* or *SAN* match the domain being visited? Default or placeholder subjects (`localhost`, empty organization, a C2 framework's default certificate) are known fingerprints.
	- Free automated CAs (Let's Encrypt) are used by everyone, attackers included. This is neutral on its own.
2. Check its validity.
	- Was it issued days ago, alongside a newly registered domain? Suspicious.
	- An unusual validity period (e.g. a self-signed certificate valid for 10 years) is also a signal.
3. Check its reputation.
	- Is its SHA1 fingerprint listed on [[#Abuse.ch|SSL Blacklist]]?
4. Pivot on it.
	- Search certificate transparency logs ([crt.sh](https://crt.sh/)) for every certificate on the domain, and other domain names listed in the same certificate. These reveal sibling phishing domains.
	- Search the fingerprint or subject on [Censys](https://search.censys.io/) or [Shodan](https://www.shodan.io/) to find other servers presenting the same certificate, which exposes more of the attacker's infrastructure.
	- For investigating TLS in network traffic, check out [[Investigating TLS]].

##### Tools

**[crt.sh](https://crt.sh/)**
- Used to gain information on [[Transport Layer Security (TLS)]] [[Certificates]].
- Can also use [Censys.io](https://search.censys.io/) or [SSL Shopper](https://www.sslshopper.com/ssl-checker.html).
- Look out for the *issuer*, the *validity*, and *subject*.

**SSL Blacklist** - [[#Abuse.ch]]

---
### Multi-IOC Platforms

These platforms cover several IOC types and are referenced from the sections above.

##### Abuse.ch

[Abuse.ch](https://abuse.ch/) has 6 tools that identify and track [[Malware]] and [[Malware#Bots and Botnet|Botnets]].
- *MalwareBazaar* is a database that collects malware. Malware can be uploaded to contribute to the database, and searching for specific malware that match certain conditions (tags, signatures, [[YARA]] rules). Can also perform searches using different hash types like [[Static Analysis#Import Hashing (IMPHASH)|IMPHASH]].
- *Feodo Tracker* is a database of the [[Command and Control|C&C]] servers that security analysts can search through and investigate any suspicious IP addresses they have come across. Additionally, they provide various [[IP]] and IOC blocklists and mitigation information to be used to prevent botnet infections.
- *SSL Blacklist* is a tool to detect malicious [[Transport Layer Security (TLS)|SSL]] handshakes by identifying malicious SSL [[Certificates]] used by botnet servers. These certificates are then added to a list to be used as a blacklist.
- *URLhaus* is a tool to share malicious URLs used for malware distribution. It contains a database of domains, URLs, hashes, and filetypes that are malicious.
- *ThreatFox* is a tool that can share IOCs associated with malware and export them in various formats.
- *YARAify* is a repository of [[YARA]] rules to identify and classify malware.

##### Talos Intelligence

[Talos Intelligence](https://talosintelligence.com/) is Cisco's threat intelligence group. Its *Reputation Center* is used to look up the reputation of [[IP]]s, domains, and file hashes.
- **Threat Intelligence & Interdiction:** Quick correlation and tracking of threats provide a means to turn simple IOCs into context-rich intel.
- **Detection Research:** Vulnerability and malware analysis is performed to create rules and content for threat detection.
- **Engineering & Development:** Provides the maintenance support for the inspection engines and keeps them up-to-date to identify and triage emerging threats.
- **Vulnerability Research & Discovery:** Working with service and software vendors to develop repeatable means of identifying and reporting security vulnerabilities.
- **Communities:** Maintains the image of the team and the open-source solutions.
- **Global Outreach:** Disseminates intelligence to customers and the security community through publications.

##### OpenCTI

[OpenCTI](https://github.com/OpenCTI-Platform/opencti) is a platform to manage CTI through storage, analysis, visualization, and presentation of Malware, threat campaigns, and IOCs, using [[STIX]]. Check out the [docs](https://docs.opencti.io/latest/).
- Can use the [[MITRE ATT&CK]] framework to structure data, and it can integrate with other tools like [[MISP]] and TheHive.
- Has [connectors](https://docs.opencti.io/latest/deployment/connectors/) that are used to ingest, enrich, or export data to the platform.
- The dashboard showcases all types of information such as Malware, TTPs, threat actors, campaigns, attack patterns, and showcases them in a divided and organized manner.

---
