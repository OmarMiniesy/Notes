### Incidents

An _Incident_ is a violation of computer security policies and is the result of an **adverse event** that has a clear intention to harm the system.
- Examples of incidents include data theft, unauthorized access, or installation of malware.
- Not all events produce incidents, and suspicious events should be investigated in order to produce incidents.

> An event is an action that occurs in a system or network, as simple as a mouse click, connection request, and more.

_Incident Handling_ is the set of procedures defined to manage and respond to security incidents.
- Incident handling plans should be comprehensive, and address various types of incidents by providing measures to identify, contain, eradicate, and recover them to restore the system.

There is an incident handling team present, also called an _incident response_ team.
- This team responds systematically to events, starting investigations if necessary and taking remediation steps.
- Incidents that are handled by this team are organized based on severities.

> NIST incident handling guide: [link](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf)

---
### Incident Handling Process

Utilizing the [[Cyber Kill Chains]] and its stages, attacker moves can be anticipated and can be countered.
- The _Incident Handling Process_ defines a set of techniques to prepare, detect, and respond to malicious activity.

The process consists of 4 stages:
1. Preparation.
2. Detection & Analysis.
3. Containment & Recovery.
4. Post-Incident Activity.

These 4 stages have two main objectives in mind, which are **investigation** and **recovery**.
- The investigation activity aims to discover the initial victim, determine what tools were used, and document what the adversary did.
- The recovery activity is used to create and implement a recovery plan.

---
### Preparation

In this phase, the organization is interested in developing an _Incident Handling_ capability.
- This capability is brought to life by first implementing the adequate protection mechanisms for the different technologies and risky areas in the organization.

For an organization to be prepared, it needs to have:
- Incident handling team.
- Workforce that aware of cybersecurity.
- Clear policies and documentation,
- The necessary software and hardware tools.

##### DMARC

This is a technology used to protect against email phishing.
- It does that by rejecting emails that pretend to originate from a given domain. It prevents email spoofing.
- It checks if an email's sender matches the domain it claims to come from (via SPF and DKIM authentication).
- The system rejects the email before it reaches the recipient. This can be dangerous if not tested properly.

Some email systems use DMARC and add a header to that evaluates to true of false based on a DMARC check.
- This can be used by _email filtering rules_ that can check the value of the DMARC header and act accordingly.
- This can be dangerous in the case of false positives.

##### Endpoint Hardening

Endpoints are the entry points for attackers, and they must be protected accordingly. Some protections that can be implemented include:
- Disable LLMNR/NetBIOS
- Implement LAPS and remove administrative privileges from regular users
- Disable or configure PowerShell in `ConstrainedLanguage` mode
- Enable Attack Surface Reduction (ASR) rules if using Microsoft Defender
- Implement whitelisting.
- Utilize host-based [[Firewall]]s.
- Deploy an EDR product.

##### Network Protection

The network should be divided and properly segmented to ensure that malicious actors cannot move easily inside.
- Different departments or different business critical components should be segregated.
- If internal resources are to face the internet, they should be placed in a DMZ.
- Utilizing technology like [[IDS & IPS]]/IPS to be able to read the traffic and identify malicious content.

If there is access to the network remotely, then security must be applied using techniques like `802.1x`.
- If there are cloud resources, then utilizing solutions similar to conditional access are required.

---
### Detection & Analysis

This phase includes:
- Detecting the incidents by utilizing logs, sensors, and security professionals.
- Sharing information and utilizing [[Cyber Threat Intelligence]].
- Full visibility into the network architecture, with its segmentation technologies in place.

Detection is done at various levels of the network:
- Network perimeter using internet facing tools like firewalls, DMZs, and IPS/IDS.
- Internal network using tools like local firewalls or host-based tools like IPS/IDS.
- At the endpoint itself using tools like EDRs and antivirus.
- At the application level using application or service logs.

To perform proper analysis of the incident after it is detected, as much information as possible should be collected about the incident.
- Date and time the incident was reported.
- Who detected the incident.
- Who reported the incident.
- How was it detected.
- What was the incident.
- The list of impacted systems/devices, and information about them.
    - Physical location
    - OS
    - [[IP]] address
    - hostnames
    - system owner
    - current state
    - system purpose
- Who accessed the impacted systems and what they did.
- Information on malware if used.

> This information allows us to build a timeline of what has happened, and provide an overall picture of the current state.

Once a [[Use Case]] is triggered based on the data that is observed, an alert is triggered, opening the next phase of [[Alert Triaging]] and investigations.
##### Investigations

To conduct an investigation and reach a valid conclusion, leads need to be discovered throughout the process itself, not just initially.
- These leads are also called _Indicators of Compromise (IOCs)_.

An IOC is a sign that an incident has occurred. It is documented in a structured manner and it represents an artifact of compromise.
- This includes IP addresses, file names, or hashes of files.
- There are known languages for documenting IOCs, such as _Yara_ and _OpenIOC_.

> IOCs can also obtained from third party vendors, and in this case they are used as [[Cyber Threat Intelligence]].

Using these IOCs we can try and look for them or similarities of them in other systems.
- In that case, we can collect and document the state of these systems to continue the investigation and discover other leads.
- This data can be collected in one of 2 methods:
    - Using live response, where data is collected from a predefined set of places to collect a large amount of useful information about the system.
    - Or shutting down the system, but this is not recommended because most of the data is lost.

---
### Containment, Recovery, and Eradication

This phase involves taking actions to prevent the spread of the incident, recover from it, and remove the threat from the system.

Containment needs to be done carefully and executed across all systems simultaneously such that attackers aren't notified that we are aware of their presence.
- There are 2 types of actions taken in containment, and these are:
    - **Short Term Containment**
    - **Long Term Containment**

_Short term containment_ includes the actions that leave a minimal footprint on the system they occur on.
- The actions done here contain the damage and provide time to develop a more concrete remediation strategy.
- These actions allow for capturing forensic evidence and images.

**Long term containment** includes actions that are persistent and leave permanent changes. Once contamination is complete, it is time to _eradicate_ the system of it.
- This is needed to ensure that the adversary is out of the system.
- This includes actions like removing the malware, rebuilding, repatching, or restoring from a backup.
- Eradication also includes system hardening.

---
