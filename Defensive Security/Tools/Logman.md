### General Notes

This is a utility for managing [[Event Tracing for Windows (ETW)]], specifically focusing on the *Tracing Sessions*.
- It allows creating, initiating, halting, and investigating sessions.

---
### Usage

To view the current sessions and investigate them, use the `-ets` flag.
```cmd
logman.exe query -ets
```

Investigating a session directly, we can see the Name, Max Log Size, Log Location, and the subscribed providers to that session.
- To do that, specify the name of the tracing session, also called the `Data Colector Set`.
```CMD
logman.exe query "EventLog-System" -ets
```

To view all available providers on the system.
```CMD
logman.exe query providers
```
- This returns a lot of responses, so use the `findstr` command to filter on what is needed.
```
logman.exe query providers | findstr "Winlogon"
```

To view the details of a single provider, provide its name.
```
logman.exe query providers Microsoft-Windows-Winlogon
```
- This shows the keywords, its GUID, the events that are available, and which processes are using that provider.

> There are GUI based alternatives for `logman`,  these are *Performance Monitor* which is found in [[System Configuration]] and the  [EtwExplorer project](https://github.com/zodiacon/EtwExplorer).

---
