### General Notes

This is an essential resource used in both identifying and remediating threats, as it:
- Archives past incidents, passing on lessons learned from previous mistakes. 
- These are then used in the broader cyber defense strategy to mitigate future threats.
- An *incident reporting framework* is needed to ensure that organizations are prepared for any dangers.

> Incident reports should be comprehensive to both technical and non-technical audiences.

Incidents can be detected in numerous ways as in [[Incident Handling]], including:
- The security systems and tools in the organization.
- Human observation.
- Third party notification.

Once incidents are detected, they should be categorized based on the attack type in order to begin allocating resources and doing the necessary prioritization.
- **Category**: [[Malware]], [[Phishing]], [[Denial of Service (DOS)]], Unauthorized access, data leak, ...
- **Severity**: Critical (P1), High (P2), Medium (P3), Low (P4).

---
### Elements of Incident Report

The report consists of:
- Executive Summary
- Technical Analysis
- Impact Analysis
- Response and Recovery Analysis
- Diagrams
- Appendix

##### Executive Summary

This is the gateway of the report that is designed for a broader audience, including non-technical stakeholders. It should contain:
- **Incident ID**: Unique identifier for the incident.
- **Incident Overview**: A concise summary of the incident's events, along with the *type* of incident. Moreover, it should include the *date/time* of the incident, *duration*, *affected systems*, and the *status* of the incident (ongoing, resolved, escalated).
- **Key Findings**: Include here the *root cause* if it was identified, write down if certain *CVEs* were exploited, and any *effects on data* (exfiltrated, compromised, jeopardized).
- **Immediate Actions**: Outline here the response measures taken, including isolating systems, identification of the root cause, engaging third party services (who and why).
- **Stakeholder Impact**: Assess the impact on the various stakeholders affected. Include here impact on availability, confidentiality, and integrity. (downtime, financial ramifications, data compromise, potential repercussions).

##### Technical Analysis

This section dissects the events that happened during the incident. It has almost al of the details of the entire report. It contains:
- **Affected Systems & Data**: Highlight all the systems and data that was accessed or compromised during the incident. For the case of data exfiltration, the volume should be stated if it is confirmed.
- **Evidence Sources & Analysis**: This contains all the evidence that was captured during analysis, the results, and the method of analysis used on the evidence. This is basically the technical walkthrough of analyzing the incident.
- **Indicators of Compromise**: Include the IOCs that have been obtained from this incident. This includes any behavior exhibited, as well [[IP]] addresses, processes, tasks, file hashes, ...
- **Root Cause Analysis**: Explain here the analysis of the root cause of the incident. This is the main cause of the security incident, such as the exploit of a certain vulnerability or of a failure point in the system.
- **Technical Timeline**: This includes the sequence of events for the incident, and it should include phases from [[Cyber Kill Chains]] or the [[MITRE ATT&CK]] as seen fit with the type of attack. It should also contain the timestamps of the *containment*, *eradication*, and *recovery* actions taken. The exact table with the timestamps and the details can be placed in the appendix.
- **Nature of the Attack**: This is a deep dive into the type of the attack, and all the TTPs that have been used by the attacker.

##### Impact Analysis

Here, the report should provide an evaluation of the effects that the incident had on the organization.
- This aims to quantify and qualify the extent of the damage caused by the incident.
- Identify which systems, processes, data, and other assets that have been compromised.
- Assess impact on business operations, such as financial loss, regulatory penalties, and reputational damage.

##### Response & Recovery Analysis

This contains the actions taken to contain, eradicate, and restore operations.

###### Immediate Response Actions

**1. Revocation of Access**
- `Identification of Compromised Accounts/Systems`: A detailed account of how compromised accounts or systems were identified, including the tools and methodologies used.
- `Timeframe`: The exact time when unauthorized access was detected and subsequently revoked, down to the minute if possible.
- `Method of Revocation`: Explanation of the technical methods used to revoke access, such as disabling accounts, changing permissions, or altering firewall rules.
- `Impact`: Assessment of what revoking access immediately achieved, including the prevention of data exfiltration or further system compromise.

**2. Containment Strategy**
- `Short-term Containment`: Immediate actions taken to isolate affected systems from the network to prevent lateral movement of the threat actor.
- `Long-term Containment`: Strategic measures, such as network segmentation or zero-trust architecture implementation, aimed at long-term isolation of affected systems.
- `Effectiveness`: An evaluation of how effective the containment strategies were in limiting the impact of the incident.

###### Eradication Measures

**1. Malware Removal**
- `Identification`: Detailed procedures on how malware or malicious code was identified, including the use of Endpoint Detection and Response (EDR) tools or forensic analysis.
- `Removal Techniques`: Specific tools or manual methods used to remove the malware.
- `Verification`: Steps taken to ensure that the malware was completely eradicated, such as checksum verification or heuristic analysis.

**2. System Patching**
- `Vulnerability Identification`: How the vulnerabilities were discovered, including any CVE identifiers if applicable.
- `Patch Management`: Detailed account of the patching process, including testing, deployment, and verification stages.
- `Fallback Procedures`: Steps to revert the patches in case they cause system instability or other issues.

###### Recovery Steps

**1. Data Restoration**
- `Backup Validation`: Procedures to validate the integrity of backups before restoration.
- `Restoration Process`: Step-by-step account of how data was restored, including any decryption methods used if the data was encrypted.
- `Data Integrity Checks`: Methods used to verify the integrity of the restored data.

**2. System Validation**
- `Security Measures`: Actions taken to ensure that systems are secure before bringing them back online, such as reconfiguring firewalls or updating Intrusion Detection Systems (IDS).
- `Operational Checks`: Tests conducted to confirm that systems are fully operational and perform as expected in a production environment.

###### Post-Incident Actions

**1. Monitoring**
- `Enhanced Monitoring Plans`: Detailed plans for ongoing monitoring to detect similar vulnerabilities or attack patterns in the future.
- `Tools and Technologies`: Specific monitoring tools that will be employed, and how they integrate with existing systems for a holistic view.

**2. Lessons Learned**
- `Gap Analysis`: A thorough evaluation of what security measures failed and why.
- `Recommendations for Improvement`: Concrete, actionable recommendations based on the lessons learned, categorized by priority and timeline for implementation.
- `Future Strategy`: Long-term changes in policy, architecture, or personnel training to prevent similar incidents.

##### Diagrams

Add all visual aids that can be used to simplify the incident:
- **Incident Flowchart**: Showcase the progression of the attack, from initial entry point and its propagation throughout the network.
- **Affected Systems Map**: The network topology highlighting the compromised nodes. Color coding works good here.
- **Attack Vector Diagram**: Showcase the attacks carried out by the attacker on the network/organization diagram.

##### Appendices

This section has supplementary material that provides additional context, evidence, and technical details. Here, the actual raw data and artifacts are placed, including:
- Log Files
- Network Diagrams (pre-incident and post-incident)
- Forensic Evidence (disk images, memory dumps, etc.)
- Code snippets
- Incident Response Checklist
- Communication Records
- Legal and Regulatory Documents (compliance forms, NDAs signed by external consultants, etc.)
- Glossary and Acronyms

---
