### General Notes

Cyber Threat Intelligence (CTI) is the grouping of data, called *IOCs*, or *Indicators of Compromise*, and is distributed by *ISACs*, or *Information and Sharing Analysis Centers*.
- This data is used by teams and companies to be able to detect threats, or build their defenses using this information.
- Threat Intel is geared towards understanding the relationship between your operational environment and your adversary.
- Threat Intel gives insights into potential adversary operations, such as their TTPs and some of their artifacts, which can be useful for [[Threat Hunting]] to inform their operations.

> Indicators of Compromise are traces that are left by attackers that could indicate that they were present, this includes [[IP]] addresses, domains, files, or even strings.

###### Threat Intelligence Categories
Threat intelligence can be categorized as **strategic**, **operational**, **technical**, or **tactical** intelligence.
- *Strategic Intelligence*: High level intel that observes the current organization's environment and outlines risks based on current or emerging threats.
- *Technical Intelligence*: These are the IOCs left by adversaries that can be used to create a baseline attack surface and develop defense mechanisms.
- *Tactical Intelligence*: This is the intelligence of the adversaries **TTPs**, allowing organizations to strengthen their security posture by understanding the methods used by attackers.
- *Operational Intelligence*: Understanding the motives and intentions behind an attack to understand the available critical assets that are to be targeted.

For threat intelligence to be useful to an organization, it needs to be:
- **Actionable**
- **Timely**
- **Relevant**
- **Accurate**

---
### CTI Lifecycle

CTI is obtained from a 6 step process that takes in raw data and transforms it into contextualized and action-oriented information. This process ensures that the CTI gathered is used to properly complete the [[Incident Handling]] process.
1. Direction
2. Collection
3. Processing
4. Analysis
5. Dissemination
6. Feedback

**Direction**: The threat intelligence gathering program is created by first defining the goals behind collecting this information. This includes:  
- Understanding the assets and business requirements that need defending. 
- Understanding the risks associated in case the activity of critical assets is interrupted.
- Understanding the sources of data to be used (log sources) whilst offering protection. 
- The current tools that are used to defend the assets.

**Collection**: Once the objectives for the CTI program have been defined, the next step is to collect this data to be utilized from several sources:
- *Internal Sources*: From internal corporate vulnerability assessments and incident reports, or system logs and events.
- *Community*: From web forms and the dark web communities.
- *External*: Threat intelligence feeds, online marketplaces, or public sources like government data.
- *Published Threat Reports*: Reports from tech companies that research actively used attacks, such as Recorded Future.

**Processing**: Once the needed sources are connected to and the data is now available, a new issue arises, and that is guaranteeing the data is presented in a unified and understanded format.
- Data from different sources regarding different topics can be represented differently, hence, a solution is needed to extract the data, sort it, organize it, and correlate it with proper tags.
- This is needed to ensure that data that is collected is used in an efficient and correct manner. This can be done using a [[SIEM]] solution.

**Analysis**: Given a solid collection of data that is adequately presented and parsed, analysts can now derive insights from this data while performing investigations.

**Dissemination**: The different stakeholders in the organization will need to consume this threat intelligence information in different formats. Hence, a process is needed to convey only the needed and required data to the appropriate teams.
- C suites and executives could utilize the *strategic intelligence*, while analysts could be more geared towards the *technical intelligence*.

**Feedback**: To conclude the operation and ensure the cycle remains functional, stakeholders need to give feedback on the efficiency and state of the threat intelligence that is being used and gathered.

---
### [[OSINT]] CTI Tools

**[Urlscan.io](https://urlscan.io/)** 
- Automates browsing and crawling of websites to record activities and interactions. 
- It provides information about the [[HTTP]] connections, the redirects present, any outgoing links, the [[Cookies]] and variables, as well as indicators ([[IP]]s, domains, and hashes) associated with the website.

**[Abuse.ch](https://abuse.ch/)**
- Has 6 tools that identify and track [[Malware]] and [[Malware#Bots and Botnet|Botnets]].
- *Malware Bazaar* is a database that collects malware. Malware can be uploaded to contribute to the database, and searching for specific malware that match certain conditions (tags, signatures, YARA rules).
- *Feedo Tracker* is a database of the C&C servers that security analysts can search through and investigate any suspicious IP addresses they have come across. Additionally, they provide various IP and IOC blocklists and mitigation information to be used to prevent botnet infections.
- *SSL Blacklist* is a tool to detect malicious [[Transport Layer Security (TLS)|SSL]] handshakes by identifying malicious SSL [[Certificates]] used by botnet servers. These certificates are then added to a list to be used as a blacklist.
- *URLhaus* is a tool to share malicious URLs used for malware distribution. It contains a database of domains, URLs, hashes, and filetypes that are malicious.
- *ThreatFox* is a tool that can share IOCs associated with malware and export them in various formats.
- *YARA IFY* is a repository of YARA rules to identify and classify malware.

**[Talos Intelligence](https://talosintelligence.com/)**
- **Threat Intelligence & Interdiction:** Quick correlation and tracking of threats provide a means to turn simple IOCs into context-rich intel.
- **Detection Research:** Vulnerability and malware analysis is performed to create rules and content for threat detection.
- **Engineering & Development:** Provides the maintenance support for the inspection engines and keeps them up-to-date to identify and triage emerging threats.
- **Vulnerability Research & Discovery:** Working with service and software vendors to develop repeatable means of identifying and reporting security vulnerabilities.
- **Communities:** Maintains the image of the team and the open-source solutions.
- **Global Outreach:** Disseminates intelligence to customers and the security community through publications.

---
