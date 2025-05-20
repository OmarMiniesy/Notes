### General Notes

This is the analysis of the volatile memory (RAM) of a computer, which deals with the live state of the system at a particular moment in time.
- However, this memory is volatile, meaning it is lost after logoffs or after shutdowns of the system. 

When [[Malware]] operates, traces or footprints are left behind in the memory.
- Analysis of the memory can uncover malicious processes, indicators of compromise, and to reconstruct the actions of malware.

> Sometimes, [[Encryption]] keys can reside in memory after they are used, which can be crucial for investigation.

Some of the data that can be obtained through memory forensics:
- *Network connections*
- *File handles and open Files*
- *Open registry keys*
- *Running processes on the system*
- *Loaded modules*
- *Loaded device drivers*
- *Command history and console sessions*
- *Kernel data structures*
- *User and credential information*
- *Malware artifacts*
- *System configuration*
- *Process memory regions*

---
### Approach to Memory Forensics

The following is a systematic approach to memory forensics following the SANS methodology.
##### Process Identification & Verification

This is where all active processes should be identified.
- However, malicious processes masquerade themselves as legitimate ones to try and hide and not be caught, such as using similar names with minor differences.

To be able to identify all processes and pin point the malicious ones, the following actions should be done:
- Enumerating all the running processes.
- Determining the *origin* of these processes from the operating system.
- Cross-referencing these processes with legitimate ones.
- Highlighting differences or suspicious processes. 

##### Dive into Process Components

