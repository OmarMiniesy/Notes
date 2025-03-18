### General Notes

DFIR, or *Digital Forensics & Incident Response*, is the practice that covers the collection of forensic artifacts from devices to investigate an incident.
- This way, footprints left by attackers can be identified to determine the extent of compromise.
- Also used to restore the environment back to a state similar to when before the incident occurred.

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

##### Evidence Preservation

All evidence and artifacts need to be preserved to maintain its integrity.
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
