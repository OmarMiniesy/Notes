### General Notes

DFIR, or *Digital Forensics & Incident Response*, is the practice that covers the collection, preservation, analysis, and presentation of digital evidence to investigate incidents.
- This way, footprints left by attackers can be identified to determine the extent of compromise, as well as provide evidence for legal proceedings.
- Digital forensics aims to reconstruct the timeline of the attack, identify the malicious activities, and uncover the truth.

Digital forensics allows for rapid action on large amounts of data to pinpoint the moment of compromise and the affected systems.
- The type of [[Malware]] or technique used is also identified.
- This allows for faster action to contain and mitigate the threat.
- Allows for an enhancement of [[Incident Handling]] strategies.

> Insights gained from digital forensics can be used for proactive [[Threat Hunting]] in the environment based on the obtained Indicators of Compromise (IOCs) and [[MITRE ATT&CK Framework#TTPs|TTPs]].

The digital forensics process involves these stages:
- *Identification*: Determining potential sources of evidence.
- *Collection*: Gathering data using forensically sound methods.
- *Examination*: Analyzing the collected data for relevant information.
- *Analysis*: Interpreting the data to draw conclusions about the incident.
- *Presentation*: Presenting findings in a clear and comprehensible manner.

DFIR is performed by experts in the two fields of:
- **Digital Forensics**: Identifying forensic artifacts or evidence of activity.
- **Incident Response**: Leveraging forensic information to respond to incidents and take the respective measures.

> Goes hand in hand with the [[Incident Handling]] process.

---
### Terminology

Basic concepts and terms that are used in digital forensics.

##### Artifacts
This is a piece of evidence that points to activities performed on a system.
- Artifacts are mainly used to support a hypothesis or claim about attacker activity.
- Artifacts can be collected from the *file system*, the *memory*, or *network activity*.
- Check out [[Windows Forensics]] and [[Web Browser Forensics]] for where to find artifacts.

##### Evidence Preservation
All evidence and artifacts need to be preserved to maintain its integrity and authenticity.
- Before performing any forensic analysis, the evidence must first be collected and write-protected, and then analysis is allowed on a *copy* of the write-protected data.

##### Chain of Custody
Making sure that the evidence is kept in secure custody, and only those with the necessary permissions and relationships with the investigation are allowed to access/see it.
- The chain of custody can be contaminated if the evidence is accessed by those not related to the investigation.
- Contaminated chain of custody leads to the questioning of the integrity of the evidence.

##### Order of Volatility
Some evidence is present on systems that are volatile, that is, the level of persistence of the data.
- While dealing with evidence, the data that is more volatile should be preserved first to ensure all the data is captured and nothing is missing.

##### Timeline Creation
Once all artifacts are collected and have their integrity maintained, all relevant data should be presented in a manner that is understandable.
- A timeline of all events that took place should be put together in order for analysis.
- A timeline provides perspective to the investigation and combines information from various sources to complete the whole attack story.

---
