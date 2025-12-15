### General Notes

This is a [[DFIR]] framework used for [[Memory Forensics]].
- Can assess images of most types of operating systems and their versions.
- Open source and written in Python.

It utilizes plugins to dissect memory images.
- A plugin is an extension that can enhance the function of Volatility by extracting specific information, or performing specific tasks on the memory images.

There are 2 versions of the framework:
- **Volatility v2** :[https://github.com/volatilityfoundation/volatility/wiki/Command-Reference](https://github.com/volatilityfoundation/volatility/wiki/Command-Reference)
- **Volatility v3**: [https://volatility3.readthedocs.io/en/latest/index.html](https://volatility3.readthedocs.io/en/latest/index.html)

> A nice cheat sheet with all of the commands [here](https://blog.onfvp.com/post/volatility-cheatsheet/).

---
### Using Volatility

##### Profiling the Image
To be able to properly analyze a memory image, its **profile** must first be identified.
- The profile outlines the operating system, version, kernel, and other important details that are essential for forensic analysis.
- The profile is also important to know so that when other plugins are to be used, they know what to look for and where.
- Check out the commands [here](https://blog.onfvp.com/post/volatility-cheatsheet/#:~:text=Volatility%203%20counterparts.-,OS%20INFORMATION,-IMAGEINFO).
##### Identifying Running Processes

Given the *profile*, we can then provide it and use another *plugin* to identify the processes that were running once the image of the memory was captured.
- This lists the memory address, the profile name, its ID and its parent ID, the time it started, and the time it exited.
- Check out the commands [here](https://blog.onfvp.com/post/volatility-cheatsheet/#:~:text=the%20requested%20information-,PROCESS%20INFORMATION,-PSLIST).
##### Identifying Network Artifacts

Given the *profile*, we can then provide it and use another *plugin* to identify network connections, showcasing [[IP]] addresses, [[Port]]s, connection state, the process ID, and the creation time of the connection.
- We can also utilize [[Memory Forensics#Kernel Objects|Pool Scanning]] to identify terminated network connections.
- Check out the commands [here](https://blog.onfvp.com/post/volatility-cheatsheet/#:~:text=process%20name%2C%20args-,NETWORK%20INFORMATION,-NETSCAN).

##### Identifying Injected Code

*Plugins* can be used to identify and extract injected code and malicious payloads from the *memory of a chosen process.*
- Using the `malfind` plugin and specifying a process, it outputs memory regions that will be likely used by [[malware]] to hide, such as:
	- Regions that are marked executable or writeable.
	- Regions that contain code injections, like shellcode or DLLs.
	- Hidden threads or *hooks* that can be used by malware.
- It outputs the process ID, its name, the memory regions with their addresses, sizes, flags, and hex dumps.
- Check out the usage of the command [here](https://blog.onfvp.com/post/volatility-cheatsheet/#:~:text=MISCELLANEOUS-,MALFIND,-Volatility%202).

> *Hooks* are used to extend or modify the behavior of software by redirecting function calls or messages. often used for injecting malware by intercepting system calls or processes. Can also be used for monitoring, logging, or modifying behavior.

#### Identifying Handles

A *Handle* is a reference to an object or file that is used by a process.
- Understanding the handles used by a process reveals the resources and objects that the process is interacting with.
- Check out the usage of the command [here](https://blog.onfvp.com/post/volatility-cheatsheet/#:~:text=path/to/dir%E2%80%9D-,HANDLES,-Volatility%202).

##### Identifying Windows Services

Within a memory dump, the running windows services can be listed and analyzed using the `svscan` plugin.
- This shows information about the services.

##### Identifying Loaded DLLs

The *DLLs, or Dynamic Link Libraries*, that are loaded into the address space of a process can be listed through the `dlllist` plugin.
- This can be used to understand which libraries and functions that the process depends on.
- Malware can inject or load malicious DLLs into legitimate processes to hide or to escalate privileges.

##### Identifying [[Windows Registry|Registry]] Hives

The registry files, or hives, can be dumped to showcase:
- User and system configuration data.
- The memory may hold the registry hive or parts of it.
- Identify persistence mechanisms by altered [[Windows Registry#Registry Keys|Registry Keys]].

---

### Integration with [[YARA]]

Volatility can be used with YARA to find matches.
1. Can be done by simply specifying the string to be found as a command line argument using the `-U` flag.
```bash
 vol.py -f /home/htb-student/MemoryDumps/compromised_system.raw yarascan -U "www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com"
```
2. Can be dony by supplying regular YARA rules using the `-y` flag.
```bash
vol.py -f /home/htb-student/MemoryDumps/compromised_system.raw yarascan -y /home/htb-student/Rules/yara/wannacry_artifacts_memory.yar
```
