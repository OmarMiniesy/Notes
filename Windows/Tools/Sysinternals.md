### General Notes

The *Sysinternals* tools are a compilation of over 70+ Windows-based tools. Each of the tools falls into one of the following categories:

- File and Disk Utilities
- Networking Utilities
- Process Utilities
- Security Utilities
- System Information
- Miscellaneous

> Can be downloaded from this [link](https://docs.microsoft.com/en-us/sysinternals/downloads/). The tool can also be used from the web on this [link](https://live.sysinternals.com/). The tool can also be used from the command prompt live without downloading it following the instructions [here](https://kamransaifullah.medium.com/sysinternals-the-other-way-around-d0d009a01e48).

---
### [Network Utilities](https://docs.microsoft.com/en-us/sysinternals/downloads/networking-utilities)

**TCPView**: A program that shows a detailed list of all [[Transport Layer]] *TCP* and *UDP* endpoints and connections.
- Similar to `netstat` tool.
- `Tcpvcon` is the command line version of this tool.

---
### [Process Utilities](https://docs.microsoft.com/en-us/sysinternals/downloads/process-utilities)

**Autoruns**: Has knowledge of auto-starting locations, or the programs that are configured to run during system bootup or login, and also for built in Windows applications.
- Has information on [[Windows Registry]] keys for startup that can be used for persistence by attackers.
- Reports Explorer shell extensions, toolbars, browser helper objects, `Winlogon` notifications, auto-start services,

**Process Explorer**: This shows the currently active processes with their owning accounts, as well as extra information depending on the mode.
 - *Handle mode* shows the handles for the selected process, and *DLL mode* shows the DLLs and opened memory mapped files, with other modes.

> Process handles are unique identifiers provided by the operating system that allows a process to interact with other processes.

**ProcDump** : CLI that monitors an application's CPU spikes and can generate crash dumps to investigate these spikes.
- Can also be done using _process explorer_, by right clicking on a process and choosing _create dump_.

**PsExec** : Allows remote process execution with full interactivity.
- This [link](https://learn.microsoft.com/en-us/sysinternals/downloads/psexec) has details on how to use it.

> Checkout [[Investigating Processes]] for more process utilities related to defensive security.

---
### [File & Disk Utilities](https://docs.microsoft.com/en-us/sysinternals/downloads/file-and-disk-utilities)

**Sigcheck**: a tool that is used to analyze file version number, timestamps, [[Digital Signatures]] and [[Certificates]].
- Can also utilize [[Cyber Threat Intelligence#OSINT CTI Tools|Virus Total]] to scan a file.
- This [link](https://learn.microsoft.com/en-us/sysinternals/downloads/sigcheck) has all the usage commands for Sigcheck.

To scan the `C:\Windows\System32` directory for any unsigned executable files:
```powershell
sigcheck -u -e C:\Windows\System32
```
- `-u` is used to show unsigned files if Virus Total is not enabled.
- `-e` is used to scan all executable files.

**Streams**: Is used to interact with the [[File System#Data Streams|Data Streams]] of files.
- This [link](https://learn.microsoft.com/en-us/sysinternals/downloads/streams) explains how to use it.
- This tool examines all of the streams of the directory/file specified, displaying their data and their sizes.
- To view the content of a stream, use the following syntax:
```
notepad <file-name>:<stream-name>
```

---
