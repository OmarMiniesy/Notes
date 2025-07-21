### General Notes

This is a high speed tracing facility provided by the operating system that utilizes buffering and logging technologies implemented in the Kernel.
- That way, it can trace events raised by user mode applications and kernel mode drivers.
- It captures more data than normal logging technologies, such as system calls, process creation, [[Windows Registry]] modifications, and more.

ETW operates with *Event Providers*, which are components that generate specific types of events and can be integrated into applications, the OS, or third party software.
- The needed and relevant event providers can be enabled, and others can be disabled; allowing us to adjust the scope of data collection. 
- These providers can be custom built to target specific requirements.

> It is light weight, making it a nice solution for real time monitoring and continuous assessment.

To retrieve logs from ETW, there is a PowerShell cmdlet called [[Get-WinEvent]] which simplifies the parsing and analysis of ETW logs.
- Also allows for filtering and event correlation mechanisms on the logs captured by ETW.
- There are also tools that can be used like [[Logman]] and [[SilkETW]].

---
### ETW Architecture & Components

The ETW uses a *publish-subscribe* model and it contains the following components:
- *Controller*
- *Provider*
- *Session*
- *Consumer*
- *Channel*
- *ETL files*

The *Controller* is responsible for controlling all ETW operations, such as initiating and terminating trace *sessions* and enabling or disabling certain *providers*.
- `logman.exe` is a famous controller that is used.

The *Provider* is responsible for generating the *Trace events* and writing them to the designated *sessions*. Applications can choose the providers they want and register them to observe the needed events. There are 4 types of providers:
- *Managed Object Format (MOF) provider*: This provider generates events that follow a specific predefined object schema.
- *Windows Software Trace Preprocessor (WPP) provider*: This provider is used by low level kernel drivers to generate events.
- *Manifest-based Providers*: These providers rely on XML format to define the structure and characteristics of events.
- *TraceLogging Providers*: These use the TraceLogging API to generate events.

A *Session* is responsible for capturing and buffering events from one or more providers. These *Sessions* then either write these events to *Trace files* or send them to *consumers*.
- A session is also called a *Trace Session*, it is an active trace environment.
- These sessions are responsible for establishing the subscriptions to the *Providers*. That is, a provider is subscribed to the session.

A *Consumer* subscribes to receive events and then processes these logs.
- By default, events are sent to the *ETL files*, but this can be changed.

An event *Channel* is used to collect and consume events. They are logical containers that organize and filter events based on their characteristics.
- Consumers choose to subscribe to specific channels and receive events from these channels.

*ETL files*, or Event Trace Logging files are used to store the events for offline analysis or investigations.
- These are the log files.

---
## Useful Providers

- `Microsoft-Windows-Kernel-Process`: This ETW provider is instrumental in monitoring process-related activity within the Windows kernel. It can aid in detecting unusual process behaviors such as process injection, process hollowing, and other tactics commonly used by malware and advanced persistent threats (APTs).
- `Microsoft-Windows-Kernel-File`: As the name suggests, this provider focuses on file-related operations. It can be employed for detection scenarios involving unauthorized file access, changes to critical system files, or suspicious file operations indicative of exfiltration or ransomware activity.
- `Microsoft-Windows-Kernel-Network`: This ETW provider offers visibility into network-related activity at the kernel level. It's especially useful in detecting network-based attacks such as data exfiltration, unauthorized network connections, and potential signs of command and control (C2) communication.
- `Microsoft-Windows-SMBClient/SMBServer`: These providers monitor Server Message Block (SMB) client and server activity, providing insights into file sharing and network communication. They can be used to detect unusual SMB traffic patterns, potentially indicating lateral movement or data exfiltration.
- `Microsoft-Windows-DotNETRuntime`: This provider focuses on .NET runtime events, making it ideal for identifying anomalies in .NET application execution, potential exploitation of .NET vulnerabilities, or malicious .NET assembly loading.
- `OpenSSH`: Monitoring the OpenSSH ETW provider can provide important insights into Secure Shell (SSH) connection attempts, successful and failed authentications, and potential brute force attacks.
- `Microsoft-Windows-VPN-Client`: This provider enables tracking of Virtual Private Network (VPN) client events. It can be useful for identifying unauthorized or suspicious VPN connections.
- `Microsoft-Windows-PowerShell`: This ETW provider tracks PowerShell execution and command activity, making it invaluable for detecting suspicious PowerShell usage, script block logging, and potential misuse or exploitation.
- `Microsoft-Windows-Kernel-Registry`: This provider monitors registry operations, making it useful for detection scenarios related to changes in registry keys, often associated with persistence mechanisms, malware installation, or system configuration changes.
- `Microsoft-Windows-CodeIntegrity`: This provider monitors code and driver integrity checks, which can be key in identifying attempts to load unsigned or malicious drivers or code.
- `Microsoft-Antimalware-Service`: This ETW provider can be employed to detect potential issues with the antimalware service, including disabled services, configuration changes, or potential evasion techniques employed by malware.
- `WinRM`: Monitoring the Windows Remote Management (WinRM) provider can reveal unauthorized or suspicious remote management activity, often indicative of lateral movement or remote command execution.
- `Microsoft-Windows-TerminalServices-LocalSessionManager`: This provider tracks local Terminal Services sessions, making it useful for detecting unauthorized or suspicious remote desktop activity.
- `Microsoft-Windows-Security-Mitigations`: This provider keeps tabs on the effectiveness and operations of security mitigations in place. It's essential for identifying potential bypass attempts of these security controls.
- `Microsoft-Windows-DNS-Client`: This ETW provider gives visibility into DNS client activity, which is crucial for detecting DNS-based attacks, including DNS tunneling or unusual DNS requests that may indicate C2 communication.
- `Microsoft-Antimalware-Protection`: This provider monitors the operations of antimalware protection mechanisms. It can be used to detect any issues with these mechanisms, such as disabled protection features, configuration changes, or signs of evasion techniques employed by malicious actors.

> There are some restricted providers that require elevated permissions to use. This includes the `Microsoft-Windows-Threat-Intelligence` provider.

---
