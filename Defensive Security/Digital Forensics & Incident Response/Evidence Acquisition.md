### General Notes

This is the phase of collecting the digital artifacts to be used for analysis, but it requires special tools in order to preserve the data's integrity, authenticity, and cleanliness.

There are several techniques used to collect forensic evidence:
- **Forensic Imaging**
- **Extracting Host Based Evidence - Memory**
- **Extracting Network Evidence**

---
### Forensic Imaging

This is a process that involves creating an exact replica of storage media, which is crucial in preserving the original state of the data.
- It is used to allow analysts to examine the original data without altering it.

Some of the tools that are used for forensic imaging:
- [FTK Imager](https://www.exterro.com/ftk-imager): It allows us to create perfect copies (or images) of computer disks for analysis, preserving the integrity of the evidence. It also lets us view and analyze the contents of data storage devices.
- [AFF4 Imager](https://github.com/Velocidex/c-aff4): It's user-friendly and compatible with numerous file systems. A benefit of the AFF4 Imager is its capability to extract files based on their creation time, segment volumes, and reduce the time taken for imaging through compression.
- `DD and DCFLDD`: Both are command-line utilities available on Unix-based systems. `DD` is a versatile tool included in most Unix-based systems by default, while DCFLDD is an enhanced version of `DD` with features specifically useful for forensics, such as hashing.
- **Virtualization Tools**: Depending on the specific virtualization solution, evidence can be gathered by temporarily halting the system and transferring the directory that houses it. Another method is to utilize the *snapshot capability* present in numerous virtualization software tools.

---
### Extracting Host Based Evidence - Memory

A system's memory is crucial in investigations, as it provides extra details, like traces of executable files and [[Malware]].
- However, this memory is volatile, meaning it is lost after logoffs or after shutdowns of the system.

Some memory acquisition solutions are:
- [WinPmem](https://github.com/Velocidex/WinPmem): The default open source memory acquisition driver for windows for a long time.
- [DumpIt](https://www.magnetforensics.com/resources/magnet-dumpit-for-windows/): A simplistic utility that generates a physical memory dump of Windows and Linux machines. On Windows, it concatenates 32-bit and 64-bit system physical memory into a single output file, making it extremely easy to use.
- [MemDump](http://www.nirsoft.net/utils/nircmd.html): Command-line utility that enables us to capture the contents of a system's RAM. It’s quite beneficial in forensics investigations or when analyzing a system for malicious activity.
- [Belkasoft RAM Capturer](https://belkasoft.com/ram-capturer): It can capture the RAM of a running Windows computer, even if there's active anti-debugging or anti-dumping protection. This makes it a highly effective tool for extracting as much data as possible during a live forensics investigation.
- [LiME (Linux Memory Extractor)](https://github.com/504ensicsLabs/LiME): A *Loadable Kernel Module (LKM)* which allows the acquisition of volatile memory. It's designed to be transparent to the target system, evading many common anti-forensic measures.

---
### Extracting Network Evidence

This is done through [[Network Analysis]], and working with [[IDS & IPS]] solutions, [[Firewall]]s, and using tools like [[Wireshark]] and [[Tcpdump]].

---
