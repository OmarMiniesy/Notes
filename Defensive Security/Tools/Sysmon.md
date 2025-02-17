### General Notes

_Sysmon_ short for _System Monitor_ is a Windows system service and driver that monitors system activity and logs it to the [[Windows Events Log]].
- System activity includes network connections, process creation, changes to files, ...
- Each type of event that is logged has a unique ID: [list of IDs](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon#events).

> It can log information that doesn't appear in the *Security Event* logs, making it a powerful tool for deep system monitoring and forensic analysis.

Sysmon uses XML configuration file, which can be edited to characterize the type of information that is visible. There are popular Sysmon configuration files which can be used
- [github.com/SwiftOnSecurity/sysmon-config](https://github.com/SwiftOnSecurity/sysmon-config).
    - Using this XML configuration file, we can enable events with certain IDs by changing the value of `onmatch` from `include` to `exclude`.
- [github.com/olafhartong/sysmon-modular](https://github.com/olafhartong/sysmon-modular)

### Installing Sysmon

1. Downloading it from the official Microsoft [documentation](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon).
2. Run this command using an administrator command prompt:
```powershell
sysmon.exe -i -accepteula -h md5,sha256,imphash -l -n
```

- To use a custom configuration file:
```powershell
sysmon.exe -c filename.xml
```

> There is a Sysmon for Linux

### Using Sysmon

To open Sysmon and view the events it logs, we open The [[Event Viewer]] application, then access:
1. Applications and Services
2. Microsoft
3. Windows
4. Sysmon

---