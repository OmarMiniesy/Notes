### General Notes

Events are actions that occur on the system.
- These actions are then saved into files called *logs*.
- In Windows systems, the logs are saved in the _Windows Event Log_.

This stores logs from different parts of the system, including:
- Applications
- [[Event Tracing for Windows (ETW)]] providers.
- Services

It provides comprehensive information about errors, events, and diagnostics.
- These logs can be of type _Application_, _System_, _Security_, _Setup_, _Forwarded Events_ or other based on their source and purpose.
- These logs can be accessed from the [[Event Viewer]] application, the [[Get-WinEvent]] cmdlet, or `Wevtutil.exe`.
- Each type of log has a different ID for the type of event it logs.

The type of events that are recorded is controlled by the *Audit Policy*.
- [Security Audit Policy](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/advanced-security-auditing)

> *Forwarded Events* has log data forwarded from other machines.

Event log data is stored in files with the `.evtx` extension.
- It uses an XML based schema.
- Stored at `C:\Windows\System32\winevt\Logs`.

To use [[ELK - Elasticsearch, Kibana, & Logstash]] as a [[SIEM]] for Windows Events Logs, view the [Winlogbeat](https://www.elastic.co/guide/en/beats/winlogbeat/current/_winlogbeat_overview.html) documentation on Elastic Docs.
- The [Exported Fields](https://www.elastic.co/guide/en/beats/winlogbeat/current/exported-fields.html) page has all the available fields that can be used to query the logs.

---
### Event Entry

Each entry in the Windows Event Log is an event, and it has this set of information:
1. `Log Name`: The name of the event log (e.g., Application, System, Security, etc.).
2. `Source`: The software that logged the event.
3. `Event ID`: A unique identifier for the event.
4. `Task Category`: This often contains a value or name that can help us understand the purpose or use of the event.
5. `Level`: The severity of the event (Information, Warning, Error, Critical, and Verbose).
6. `Keywords`: Keywords are flags that allow us to categorize events in ways beyond the other classification options. These are generally broad categories, such as "Audit Success" or "Audit Failure" in the Security log. Can also allow us to filter for specific types of events.
7. `User`: The user account that was logged on when the event occurred.
8. `OpCode`: This field can identify the specific operation that the event reports.
9. `Logged`: The date and time when the event was logged.
10. `Computer`: The name of the computer where the event occurred.
11. `XML Data`: All the above information is also included in an XML format along with additional event data.

---
