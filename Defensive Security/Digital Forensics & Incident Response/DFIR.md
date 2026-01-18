### General Notes

DFIR, or *Digital Forensics & Incident Response*, is the practice that covers the collection, preservation, analysis, and presentation of digital evidence to investigate incidents.
- This way, footprints left by attackers can be identified to determine the extent of compromise, as well as provide evidence for legal proceedings.
- Digital forensics aims to reconstruct the timeline of the attack, identify the malicious activities, and uncover the truth.

Digital forensics allows for rapid action on large amounts of data to pinpoint the moment of compromise and the affected systems.
- The type of [[Malware]] or technique used is also identified.
- This allows for faster action to contain and mitigate the threat.
- Allows for an enhancement of [[Incident Handling]] strategies.

> Insights gained from digital forensics can be used for proactive [[Threat Hunting]] in the environment based on the obtained Indicators of Compromise (IOCs) and [[MITRE ATT&CK#TTPs|TTPs]].

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
### Artifacts

This is a piece of evidence that points to activities performed on a system.
- Artifacts are mainly used to support a hypothesis or claim about attacker activity.
- Artifacts can be collected from the *file system*, the *memory*, or *network activity*.

Check out for where to find artifacts:
- [[Windows Forensics]]
- [[Windows Registry Forensics]]
- [[Web Browser Forensics]]
- [[Memory Forensics]]
- [[Disk Forensics]]
- [[Linux Forensics]]

---
### Evidence Preservation and Acquisition

All evidence and artifacts need to be preserved to maintain its integrity and authenticity.
- Before performing any forensic analysis, the evidence must first be collected and write-protected, and then analysis is allowed on a *copy* of the write-protected data.

Some tools used in [[Rapid Triage]]:
- [[KAPE]]
- [[Velociraptor]].

**Forensic Imaging**: This is a process that involves creating an exact replica of storage media, which is crucial in preserving the original state of the data. Some of the tools used to do this:
- [FTK Imager](https://www.exterro.com/ftk-imager): It allows us to create perfect copies (or images) of computer disks for analysis, preserving the integrity of the evidence. It also lets us view and analyze the contents of data storage devices.
- [AFF4 Imager](https://github.com/Velocidex/c-aff4): It's user-friendly and compatible with numerous file systems. A benefit of the AFF4 Imager is its capability to extract files based on their creation time, segment volumes, and reduce the time taken for imaging through compression.
- `DD and DCFLDD`: Both are command-line utilities available on Unix-based systems. `DD` is a versatile tool included in most Unix-based systems by default, while DCFLDD is an enhanced version of `DD` with features specifically useful for forensics, such as hashing.
- **Virtualization Tools**: Depending on the specific virtualization solution, evidence can be gathered by temporarily halting the system and transferring the directory that houses it. Another method is to utilize the *snapshot capability* present in numerous virtualization software tools.

**[[Disk Forensics]]**: This is done through tools like *Autopsy* to understand the file structure of an image, as well as create a timeline of the events happened.
- Includes finding and recovering deleted files.

[[Windows Registry Forensics]] : This is used to extract the windows registry for evidence of persistence, program execution history, and changes to system configuration.
- Autopsy
- FTK Imager
- [[KAPE]]

Once registry is extracted, we can now view the files of the registry for analysis. This can be done using tools like:
- [Registry Explorer by Eric Zimmerman](https://ericzimmerman.github.io/#!index.md): Can load multiple hives and adds data from transactional logs.
- [RegRipper](https://github.com/keydet89/RegRipper3.0): Takes a hive as input and outputs a report with the important keys and values. Does not take transactional logs into account.

[[Memory Forensics]]: A system's memory is crucial in investigations, as it provides extra details, like traces of executable files and [[Malware]]. However, this memory is volatile, meaning it is lost after logoffs or after shutdowns of the system. Memory forensics deals with the live state of a system at a particular moment in time. 

Some memory acquisition solutions are:
- [[Volatility]]
- [WinPmem](https://github.com/Velocidex/WinPmem): The default open source memory acquisition driver for windows for a long time.
- [DumpIt](https://www.magnetforensics.com/resources/magnet-dumpit-for-windows/): A simplistic utility that generates a physical memory dump of Windows and Linux machines. On Windows, it concatenates 32-bit and 64-bit system physical memory into a single output file, making it extremely easy to use.
- [MemDump](http://www.nirsoft.net/utils/nircmd.html): Command-line utility that enables us to capture the contents of a system's RAM. It’s quite beneficial in forensics investigations or when analyzing a system for malicious activity.
- [Belkasoft RAM Capturer](https://belkasoft.com/ram-capturer): It can capture the RAM of a running Windows computer, even if there's active anti-debugging or anti-dumping protection. This makes it a highly effective tool for extracting as much data as possible during a live forensics investigation.
- [LiME (Linux Memory Extractor)](https://github.com/504ensicsLabs/LiME): A *Loadable Kernel Module (LKM)* which allows the acquisition of volatile memory. It's designed to be transparent to the target system, evading many common anti-forensic measures.

**Network Forensics**: This is done through [[Network Analysis]], and working with [[IDS & IPS]] solutions, [[Firewall]]s, and using tools like [[Wireshark]] and [[Tcpdump]].

---
### Chain of Custody

Making sure that the evidence is kept in secure custody, and only those with the necessary permissions and relationships with the investigation are allowed to access/see it.
- The chain of custody can be contaminated if the evidence is accessed by those not related to the investigation.
- Contaminated chain of custody leads to the questioning of the integrity of the evidence.

---
### Order of Volatility

Some evidence is present on systems that are volatile, that is, the level of persistence of the data.
- While dealing with evidence, the data that is more volatile should be preserved first to ensure all the data is captured and nothing is missing.

---
### Timeline Creation

Once all artifacts are collected and have their integrity maintained, all relevant data should be presented in a manner that is understandable.
- A timeline of all events that took place should be put together in order for analysis.
- A timeline provides perspective to the investigation and combines information from various sources to complete the whole attack story.

---
