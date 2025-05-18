### General Notes

*System Resource Usage Monitor (SRUM)* is a database in the Windows operating system that stores information about system and application resource utilization.
- It collects statistics on the execution of binaries.

Can be used in [[DFIR]] to determine the CPU usage, memory usage, network activity, and energy consumption of an application to determine if it is being used in a malicious manner.
- Check out [[Windows Forensics#System Resource Usage Monitor (SRUM)|SRUM Windows Forensics]] for more details.

It is located in `C:\Windows\System32\sru` directory and it is stored using `etl` format.
- There is a SQLite database file called `sru.db`
- Can be opened using tools like *Microsoft Message Analyzer* or the *Windows Performance Toolkit*.

---
