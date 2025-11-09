### General Notes

An incident is a *violation*, that of policy, law, or unacceptable acts affecting assets, computers, or networks.
- Described in this document are the 6 steps of incident handling and what to do in each phase.
- It also contains an incident handler's checklist to ensure the correct steps are followed in each phase.

> Document [Link](https://dl.icdst.org/pdfs/files3/d60a0c473353813ed1f32c4faefedbd6.pdf).

The *CIRT*, or Cyber Incident Response Team, is the group that leads and coordinates the technical and operational response to cyber incidents.

---
### Preparation

This is the phase where the team is to be prepared to handle the incident once it is detected.
- Preparation determines how well the team will respond to that incident.
- Listed below are the things that should be present and created during this phase.

###### Policy

A *policy* contains a written set of principles, rues, and followed practices within an organization. 
- The policy mainly dictates what can and what cannot be done.
- Based on the existing policy and its violation, we can say that an incident has occurred.

###### Response Plan

This is a plan to handle incidents after policies have been established. 
- Different incidents should have different handling strategies based on their impact, which is determined by the incident *prioritization*.
- The organizational impact should be properly outlined and showcased to receive the management buy in. A crucial group that will give the necessary resources for the CIRT.

###### Communication

A communication plan is needed to outline who is to be contacted and how, and at what times.
- This plan is necessary to ensure that incidents are responded to in due time and by the people with the relevant experience and expertise.

###### Documentation

This is an essential element of incident response that should be able to answer any and all questions asked about the incident.
- It should include all the actions taken, by whom, and on what system.
- This is used later in the lessons learned phase of incident response, and can be used to take legal action.

###### Team

The CIRT team should consist of a variety of people with various responsibilities and roles.
- It should include the technical IT staff that will respond to the incident, as well legals, HR, and others.

###### Access Control

This is ensuring that the CIRT members have the appropriate permissions to access systems during incident response.
- These permissions should be added/removed as needed during the incident and after it.

###### Tools

All of the tools that could be needed while handling an incident should be contained in a _jump bag_ that can be quickly grabbed by the CIRT members.
- These tools comprise any type of software and/or hardware that can be utilized during the incident.

The _Jump Bag_ should include:
- The _Incident Handling Journal_: Used to document who, what, where, why, and how.
- Contacts for all CIRT members.
- USB Drives.
- Bootable USD drive with up to date software that can be used on devices affected by the incident.
- Laptop with forensic software, anti-malware utilities, and internet access.
- Computer and Network tool kits: To be used to perform any actions on the physical network for any reason.
- Hard duplicators with write capabilities to create forensic copies of images.

###### Training

The members of the CIRT should be regularly trained and exercise on drills to be ready and well prepared when an incident arrives.

---
### Identification

This is the phase where the incident is detected and its scope identified.
- This is determined by understanding that it deviates from normal behavior by analyzing and gathering events from various sources like logs, error messages, or security systems like Firewals and IDS.

Once events are analyzed and determined to be incidents, they should be reported as soon as possible to allow the CIRT enough time to react to the incident and collect evidence for the next steps.
- Coordination between members of the CIRT is needed, as well as with management, especially if there is significant impact on operations. 
- It is best practice that there are 2 incident handlers available, where the primary identifies and assesses the incident, and the other collects evidence.

---
### Containment

This phase is needed to limit the damage caused by the incident and to prevent any further damage.
- It is needed to mitigate the incident and prevent the destruction of evidence.
- There are three steps, being _short-term containment_, _system back-up_, and _long-term containment_.

**Short-Term Containment**:
- This step is used to limit the damage as soon as possible.
- This has straightforward activities, like isolating infected network segments, taking down servers, or rerouting traffic.
- These are not long term solutions to the problem, they are only used to limit the impact of the incident before it gets worse.

**System Back Up**: This action is necessary to be done before wiping or taking a forensic image of a system for a couple of reasons:
1. To retain forensic evidence for analysis and legal purposes.
2. To create reliable copies that can be used to restore or rebuild systems.

**Long-Term Containment**: 
- This is the phase where corrective actions are taken to temporarily fix the systems, essentially returning them to production to be used.
- Examples include removing persistence accounts, any backdoors, installing quick security patches, and limiting the spread and escalation of the incident.

---
### Eradication

This is the phase where the systems are restored and any malicious artifacts are removed.
- Proper steps need to be taken to ensure that the malicious content was effectively removed from the systems. This includes scanning affected systems with anti-malware software and others to ensure that everything has been properly eradicated.
- Example actions include restoring systems to the captured base images taken before, and then installing patches and disabling any unused services to harden the system.

---
### Recovery

This is the phase where the affected systems are brought back to the production environment, with the necessary controls to ensure that the incident will not happen again.
- The systems that are being restored should be tested, monitored, and validated to ensure that they are not going to be reinfected.

---
### Lessons Learned




---










