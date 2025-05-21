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

##### Kernel Objects
These are data structures that represent system resources that is stored in the kernel-mode memory space.
- They provide a unified way for the operating system to handle processes, files, network connections, drivers, and more.
- Each kernel object has a unique *pool tag* to be able to identify it.

**Pool Scanning:** We can utilize memory scanning tools like [[Volatility]] to scan the memory and look for these kernel objects using these *pool tags*.
- They can reveal hidden or terminated artifacts that can be missed by normal user inspection.

---
### Approach to Memory Forensics

The following is a systematic approach to memory forensics following the SANS methodology.
- This can be done using the [[Volatility]] framework.
##### Process Identification & Verification

This is where all active processes should be identified.
- However, malicious processes masquerade themselves as legitimate ones to try and hide and not be caught, such as using similar names with minor differences.

To be able to identify all processes and pin point the malicious ones, the following actions should be done:
- Enumerating all the running processes.
- Determining the *origin* of these processes from the operating system.
- Cross-referencing these processes with legitimate ones.
- Highlighting differences or suspicious processes. 

##### Dive into Process Components

Once *potentially* rogue processes are flagged out, the *DLLs (Dynamically Linked Libraries)* and *handles* should be assessed.
- [[Malware]] utilize DLLs to conceal their activities.

To assess these components, the following actions should be done:
- Examine the DLLs linked to the suspicious process.
- Check for unauthorized or malicious DLLs.
- Investigate for DLL injections or hijacking.

##### Analyze Network Activity

Malware operate in stages, and one stage is to connect to the *Command and Control C2* beacon to exfiltrate data or receive/send commands over the internet.

To uncover such activity, the following can be done:
- Review active/passive network connections in the system memory.
- Identify and document external [[IP]] addresses and any domains.
- Study the communication and determine its purpose to:
	- Validate the process legitimacy.
	- Check if network connectivity is usually exercised by this process.
	- Trace back to the parent process, and evaluate its behavior.

##### Code Injection Detection

Adversaries can perform *process hollowing* or utilize *unmapped memory* sections. To investigate this, the following can be done:
- Memory analysis tools or signs of these techniques.
- Identify processes that occupy unusual memory spaces.

##### Rootkit Discovery

Rootkits embed deep into the operating system and they grant persistence for the adversary, as well as privilege escalation. This can be analyzed by:
- Scanning for signs of rootkit activity or operating system alterations.
- Identify processes or drivers operating at high privileges or trying to hide their actions.

##### Extraction of Suspicious Elements

After any suspicious processes, drivers, or executables are located, they should be isolated and extracted. This can be done by:
- Dumping the memory components.
- Storing them for examination using forensics tools.

---
