### General Notes

This is a knowledge base of the detection *analytics*, ways to detect malicious behaviors, based on the [[MITRE ATT&CK]] techniques.
- The analytics are basically queries or methods to detect these attack techniques.
- Also includes the implementations of these analytics for tools like [[Splunk]].

Each CAR entry includes the following:
- The *ATT&CK technique* it maps to, with the *sub-technique*, and *tactic*.
- A *detection idea or query* (e.g., a Splunk, Elastic, or SQL-style query)
- Required *data sources* (e.g., process creation logs, PowerShell logs)
- The *platform* it applies to (Windows, Linux, etc.)

> CAR is a great place for finding analytics that can help in detecting and mitigating attacks, but it is not a replacement for the [[MITRE ATT&CK]].

---
