### General Notes

EDRs are designed to monitor, detect, & respond to threats at the endpoint level. Their purpose is to :
- Continuously monitor activity and system behavior.
- Collect and store logs about system activity.
- Threat detection to identify suspicious behavior.
- [[DFIR]] and to track and understand how attacks happen.
- Take action and respond to threats.

> An example of an EDR is an anti-virus.

An EDR is known mainly for:
- **Visibility**: EDRs collect detailed data from endpoints and present this data in a structured format, often in a tree format with activities based on a timeline of events. 
- **Detection**: Utilizes signature based detections, behavior based detections, and AI capabilities to identify deviations from baseline behavior and any malicious behavior.
- **Response**: EDRs allow analysts to take action against detected threats on the endpoint from a central console.

> For detection mechanisms used, check out these [[IDS & IPS#Detection Strategies|Detection Strategies]].

EDRs operate by using an architecture that contains a central console and multiple agents on several endpoints.
- The agents are deployed on the endpoints and they monitor all activities on the endpoint, and report this information to the central console in real time. They also can do some basic detections on the endpoint. Also known as *sensors*.
- The EDR console is the central data store that is responsible for analysis and taking corrective action. Utilizes [[Cyber Threat Intelligence]] to match with the collected data to check for known malicious activity.

---
### Telemetry Collection

EDR agents collect telemetry from the endpoints they are installed on:
- *Process Information*: process execution, running and idle processes, parent-child relationships.
- *Network Connections*: network connections are monitored, identifying connections to C2 servers, unusual [[Port]] usage, data exfiltration, or lateral movement.
- *Command Line Activity*: all commands executed in the CMD or PowerShell or others.
- *File & Folder Modification*.
- *[[Windows Registry]] Modifications*.

> Using this information, the normal expected behavior can be identified as a reference, allowing us to determine outliers that could threaten the organization. This is known as *baselining*.

---
### Response Methods

After a threat is detected, manual or automated responses can be taken to block malicious behavior.
- **Host Isolation**: Isolate the endpoint from the network to *contain* the malicious activity.
- **Process Termination**: Sometimes, host isolation is not feasible due to business or technical reasons. Hence, process termination is used to neutralize the malicious activity. However, this should be done with caution to not cause a denial of availability.
- **Quarantine**: Malicious files can be quarantined, by moving it to an isolated location where it cannot be executed. There, it can be reviewed to decide whether to remove it or to return it.
- **Remote Access**: Obtain remote access to the shell of an endpoint to gain deeper visibility and perform any needed action by running scripts.
- **Artifact Collection**: For [[DFIR]], evidence should be obtained.

---
