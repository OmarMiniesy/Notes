### General Notes

This is a *proactive*, human-led, and hypothesis driven approach to search for security threats that evade the existing security solutions.
- Uncovering threats that are present inside the network that have not yet been detected by prioritizing anticipation over reaction.
- It can also be a *reactive* approach to search for evidence related to incidents in the network.

> The team between an actual security breach and its detection is called *dwell time*.

Threat hunting operations should be done in a periodic manner, but these instances require an immediate hunting operation:
- New information about adversaries or vulnerabilities is known.
- When new Indicators of Compromise are known that are associated with a known adversary.
- When multiple concurrent network anomalies take place.
- During incident response.

###### Minimizing Dwell Time
Threat hunting is used to minimize dwell time by recognizing malicious entities at the earliest stages of the [[Cyber Kill Chains]], to prevent them from expanding and growing inside the network.
1. The process starts by first gathering all assets that could be targets.
2. Analyze the [[MITRE ATT&CK#Framework Structure|TTPs]] (Tactics, Techniques, & Procedures) that are employed by adversaries using [[Cyber Threat Intelligence]].
3. The identified artifacts are then isolated and validated if any activity is exhibited that deviates from the established baseline.

###### Threat Hunting & Incident Response
Threat hunting goes hand in hand with [[Incident Handling]] in each of its phases:
- **Preparation**: During this phase of Incident Handling, threat hunting teams are set up with guidelines and rules of engagement. Threat hunting should be combined with the existing policies and procedures of incident response.
- **Detection & Analysis**: Investigations are augmented and enriched using the findings of threat hunting to identify the significance of the identified *IOCs* (Indicators of Compromise), or obtain new findings and evidence that has been missed.

---
### Threat Hunting Process

1. **Planning and Preparation**: This is where the *threat landscape is understood*, along with the business critical requirements, and the [[Cyber Threat Intelligence]] insights are documented and followed up on. It also includes *preparing the environment* for threat hunting by enabling logging and ensuring that threat hunting tools are set up such as [[IDS & IPS]], [[SIEM]], and [[Endpoint Detection and Response (EDR)]]s.
2. **Hypothesis Formulation**: This is where *educated predictions* are made that will guide the hunting journey. Hypotheses are created by observing threat intelligence updates, alerts from the set up security tools, and industry updates.
3. **Design the Hunting Strategy**: The data sources that will be analyzed (network logs, application logs, [[Domain Name System (DNS)]] logs, ...), the methodologies to be followed, the tools to be used, and the indicators of compromise (IOCs) that will be hunted for.
4. **Data Gathering and Examination**: The data that is to be analyzed is gathered here and analyzed using the tools and methodologies defined in the strategy. This is where the *active threat hunt occurs*, and this is where the evidence is collected to either support/refute the hypothesis.
5. **Hypothesis Testing and Finding Evaluation**: After analyzing the data, a decision regarding the hypothesis can be made. It also includes understanding the behavior of the detected threats, identifying the affected systems, and determining the impact of threats.
6. **Mitigating Threats**: Remediation action is taken on confirmed threats, such as isolation, malware elimination, vulnerability patching, or configuration modifications.
7. **Post Hunt Activities**: The findings, methods, outcomes, and all data should be documented and published. This also includes utilizing the gained knowledge to improve current technologies, threat intelligence, and security policies.

---
