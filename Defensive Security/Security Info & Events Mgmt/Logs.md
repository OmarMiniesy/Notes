### Log Types

A list of the common log types includes:
- **Application Logs:** Messages about specific applications, including status, errors, warnings, etc.
- **Audit Logs:** Activities related to operational procedures crucial for regulatory compliance.
- **Security Logs:** Security events such as logins, permissions changes, firewall activity, etc.
- **Server Logs:** Various logs a server generates, including system, event, error, and access logs.
- **System Logs:** Kernel activities, system errors, boot sequences, and hardware status.
- **Network Logs:** Network traffic, connections, and other network-related events.
- **Database Logs:** Activities within a database system, such as queries and updates.
- **Web Server Logs:** Requests processed by a web server, including URLs, response codes, etc.

---
### Log Formats

A log format is defined by the structure & organization, encoding used, the entry delimitation used, and the fields included. The formats can be *Semi-Structured*, *Structured*, and *Unstructured*.

**Semi-structured logs**: Contain structured or unstructured data.
- Syslog: A logging protocol used for system and network logs.
- [[Windows Events Log]]: This is a proprietary log used by Microsoft for Windows.

**Structured logs**: Follows a strict and standard format.
- CSV & TSV
- JSON
- Extended Log Format (ELF): Used for web server logging. Used by Microsoft Internet Information Services (IIS) web server.
- [[XML]]

**Unstructured logs**: This is for free form text. Hard to parse.
- NCSA Common Log Format (CLF): A web server log format for client requests. Used by [[Apache]] [[HTTP]] server.
- NCSA Combined Log Format (Combined): An extension of CLF adding fields like `referrer` and `user agent`. Used by Nginx HTTP server.

---
### Log Standards

- [**Common Event Expression (CEE):**](https://cee.mitre.org/) This standard, developed by MITRE, provides a common structure for log data, making it easier to generate, transmit, store, and analyze logs.
- **[OWASP Logging Cheat Sheet:](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)** A guide for developers on building application logging mechanisms, especially related to security logging.
- **[Syslog Protocol:](https://datatracker.ietf.org/doc/html/rfc5424)** Syslog is a standard for message logging, allowing separation of the software that generates messages from the system that stores them and the software that reports and analyses them.
- **[NIST Special Publication 800-92:](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-92.pdf)** This publication guides computer security log management.
- **[Azure Monitor Logs:](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/data-platform-logs)** Guidelines for log monitoring on Microsoft Azure.
- **[Google Cloud Logging:](https://cloud.google.com/logging/docs)** Guidelines for logging on the Google Cloud Platform (GCP).
- **[Oracle Cloud Infrastructure Logging:](https://docs.oracle.com/en-us/iaas/Content/Logging/Concepts/loggingoverview.htm)** Guidelines for logging on the Oracle Cloud Infrastructure (OCI).
- **[Virginia Tech - Standard for Information Technology Logging:](https://it.vt.edu/content/dam/it_vt_edu/policies/Standard_for_Information_Technology_Logging.pdf)** Sample log review and compliance guideline.

---
### Unix Logs

Check out [[Linux Forensics]] and [[Linux Privilege Escalation]] for more details.

> Logs are present in the `/var/log/` directory on Unix systems. Third party logs are also present inside this directory within their own directories.

###### `/var/log/auth.log` 
 Has authorization information about user logins and authentication mechanisms used.
- Has the date, followed by the [[IP]] of the machine that the log was generated on, the process and process ID that generated the log , the description of the log.
- There can be several `auth.log.#` files, and there can be zipped files. Analyze all.
- All commands that are run using `sudo` are stored in this log. Can be obtained by `grep <COMMAND>`.
###### `/var/log/*tmp` 
The `*tmp` files that hold logon history information.
- `/var/log/btmp` logs failed logon attempts.
- `/var/run/utmp` logs stats, including successful logons, boot time, logouts, and other events of the _current state_ of the system — i.e., since its last boot.
- `/var/log/wtmp` contains historical content of `utmp`, allowing you to peek back in time. Check `wtmp` [man page](https://linux.die.net/man/5/wtmp) for information on how to read the entries, and the types of entries.

The content in this file follows the `utmp` struct format.
- To read these files, either use `last` or use `utmpdump`.

```
sudo last -f /var/log/wtmp
```

###### `/var/log/kern`
Stores kernel related events.

###### `/var/log/httpd`
Stores [[HTTP]] request/response logs and any errors.
- Also has *Apache* related logs, which can also be found in `/var/log/apache`.

###### `/var/log/cron`
Events related to cron jobs.

###### `/var/log/syslog*`
Syslog contains messages recorded by the host about system activity. The detail of these messages is configurable by the logging level.
- It has information about system time, system name, process that created the log, and log details.
- There is an asterisk at the end due to log rotation, so check all files.

---
### Windows Logs

All windows logs can be viewed through the [[Event Viewer]] utility and can be analyzed using tools like [[Get-WinEvent]].

###### `C:\Windows\System32\winevt\Logs`

Has [[Windows Events Log]]s files.

---
