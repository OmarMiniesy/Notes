### General Notes

_Sysmon_ short for _System Monitor_ is a Windows system service part of the [[Sysinternals]] tool suite and driver that monitors system activity and logs it to the [[Windows Events Log]].
- System activity includes network connections, process creation, changes to files..
- Each type of event that is logged has a unique ID: [list of IDs](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon#events).

> It can log information that doesn't appear in the *Security Event* logs, making it a powerful tool for deep system monitoring and forensic analysis.

Sysmon uses XML configuration file, which can be edited to characterize the type of information that is visible. There are popular Sysmon configuration files which can be used
- [github.com/SwiftOnSecurity/sysmon-config](https://github.com/SwiftOnSecurity/sysmon-config).
    - Using this XML configuration file, we can enable events with certain IDs by changing the value of `onmatch` from `include` to `exclude`.
- [github.com/olafhartong/sysmon-modular](https://github.com/olafhartong/sysmon-modular)


> Sysmon resources [link](https://github.com/jymcheong/SysmonResources).

### Installing Sysmon

1. Downloading it from the official Microsoft [documentation](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon).
2. Run this command using an administrator command prompt:
```powershell
sysmon.exe -i -accepteula -h md5,sha256,imphash -l -n
```

To use a custom configuration file: (MUST)
```powershell
sysmon.exe -c filename.xml
```
- Once the configuration file is changed and ran with Sysmon, the logs that it captures are now visible to be analyzed.


> There is a Sysmon for Linux.

### Using Sysmon

To open Sysmon and view the events it logs, we open The [[Event Viewer]] application, then access:
1. Applications and Services
2. Microsoft
3. Windows
4. Sysmon
5. Operational

To have better filtering control, the [[Get-WinEvent]] and `wevutil.exe` PowerShell modules are better to use. Example filters using `XPath` are:
- Filter by Event ID: `*/System/EventID=<ID>`
- Filter by XML Attribute/Name: `*/EventData/Data[@Name="<XML Attribute/Name>"]`
- Filter by Event Data: `*/EventData/Data=<Data>`

> [XPath Documentation](https://learn.microsoft.com/en-us/previous-versions/dotnet/netframework-4.0/ms256115(v=vs.100)).

---
### Sysmon Event Codes & Description

To list all the `EventCodes` in [[Splunk]] for Sysmon using [[Splunk Processing Language (SPL)]]:
```SPL
index="main" sourcetype="WinEventLog:Sysmon" | stats count by EventCode
```

- [Sysmon Event ID 1 - Process Creation](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90001): The process creation event provides extended information about a newly created process. The full command line provides context on the process execution. The `ProcessGUID` field is a unique value for this process across a domain to make event correlation easier. The hash is a full hash of the file with the algorithms in the `HashType` field.
- [Sysmon Event ID 2 - A process changed a file creation time](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90002): Helpful in spotting "time stomp" attacks, where attackers alter file creation times. Bear in mind, not all such actions signal malicious intent.
- [Sysmon Event ID 3 - Network connection](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90003): A source of abundant noise since machines are perpetually establishing network connections. We may uncover anomalies, but let's consider other quieter areas first.
- [Sysmon Event ID 4 - Sysmon service state changed](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90004): Could be a useful hunt if attackers attempt to stop Sysmon, though the majority of these events are likely benign and informational, considering Sysmon's frequent legitimate starts and stops.
- [Sysmon Event ID 5 - Process terminated](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90005): This might aid us in detecting when attackers kill key processes or use sacrificial ones. For instance, Cobalt Strike often spawns temporary processes like `werfault`, the termination of which would be logged here, as well as the creation in ID 1.
- [Sysmon Event ID 6 - Driver loaded](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90006): A potential flag for BYOD (bring your own driver) attacks, though this is less common. Before diving deep into this, let's weed out more conspicuous threats first. 
- [Sysmon Event ID 7 - Image loaded](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90007): Allows us to track `dll` loads, which is handy in detecting DLL hijacks.
- [Sysmon Event ID 8 - CreateRemoteThread](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90008): Potentially aids in identifying injected threads. While remote threads can be created legitimately, if an attacker misuses this API, we can potentially trace their rogue process and what they injected into.
- [Sysmon Event ID 10 - ProcessAccess](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90010): Useful for spotting remote code injection and memory dumping, as it records when handles on processes are made.
- [Sysmon Event ID 11 - FileCreate](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90011): With many files being created frequently due to updates, downloads, etc., it might be challenging to aim our hunt directly here. However, these events can be beneficial in correlating or identifying a file's origins later.
- [Sysmon Event ID 12 - RegistryEvent (Object create and delete)](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90012) & [Sysmon Event ID 13 - RegistryEvent (Value Set)](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90013): While numerous events take place here, many registry events can be malicious, and with a good idea of what to look for, hunting here can be fruitful.
- [Sysmon Event ID 15 - FileCreateStreamHash](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90015): Relates to file streams and the "Mark of the Web" pertaining to external downloads, but we'll leave this aside for now.
- [Sysmon Event ID 16 - Sysmon config state changed](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90016): Logs alterations in Sysmon configuration, useful for spotting tampering.
- [Sysmon Event ID 17 - Pipe created](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90017) & [Sysmon Event ID 18 - Pipe connected](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90018): Record pipe creations and connections. They can help observe malware's `interprocess` communication attempts, usage of [PsExec](https://learn.microsoft.com/en-us/sysinternals/downloads/psexec), and SMB lateral movement.
- [Sysmon Event ID 22 - DNSEvent](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90022): Tracks DNS queries, which can be beneficial for monitoring beacon resolutions and DNS beacons.
- [Sysmon Event ID 23 - FileDelete](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90023): Monitors file deletions, which can provide insights into whether a threat actor cleaned up their malware, deleted crucial files, or possibly attempted a ransomware attack.
- [Sysmon Event ID 25 - ProcessTampering (Process image change)](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon): Alerts on behaviors such as process herpadering, acting as a mini AV alert filter.

---
