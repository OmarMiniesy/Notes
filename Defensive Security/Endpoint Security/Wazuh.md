### General Notes

Wazuh is an open source [[Endpoint Detection and Response (EDR)]] that operates by deploying *Wazuh agents* on the endpoints to be secured.
- There is then a singular Wazuh instance that manages these agents, called the *management module*.

*Wazuh Agents* monitor the processes that take place on a device and they record the events that take place.
- These agents are deployed and are connected to the *Wazuh management server* to send the logs to.

> Alerts are stored in `/var/ossec/logs/alerts/alerts.log` in the management server.

---
### Features

##### Vulnerability Scanning

Can be used to perform vulnerability scanning and assessments on the devices.
- The *vulnerability scanner module* will perform a vulnerability scan when the agent is first installed.
- It is then configured to run at set intervals.

> Vulnerability assessments work by collecting the versions of the software and the operating systems that are running, and then comparing them with a CVE database to check if anything has vulnerabilities.

##### Policy Auditing

Can be used to perform audits against many frameworks and legislations such as:
- [[MITRE ATT&CK]]
- HIPAA
- NIST
- GDPR
- CSA

For each of these standards, metrics are produced in dashboards to show how compliant the device is with the configured frameworks.

---
