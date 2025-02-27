### General Notes

A [[SIEM]] _use case_ allows the SOC team to identify potential security incidents by illustrating a specific situation/scenario.
- Based on the log data generated and used by the SIEM, the use cases are developed to make sense of the events and correlate them to match and detect for incidents.

> Use cases are used to generate alerts. These alerts are then attended to by the SOC team, or are acted upon by some automation rules or workflows.

---
### Creating a Use Case

To properly define a use case and ensure its efficiency, they need to be created following a cycle that has several stages:

1. **Requirements**: The purpose of the use case needs to be concrete and understood, such that the correct alerts are generated at the right time.
2. **Data Points**: The data sources that generate the logs specific to this use case need to be outlined, and the content of these logs needs to be sufficient.
3. **Log Validation**: The logs need to be verified to ensure they contain the necessary information for the use case tow operate. They also need to be validated to ensure that the logs really are produced from the chosen data points.
4. **Design and Implementation**: The use case should be designed by specifying the _conditions_ that are needed to generate an alert. The design should also ensure that event _aggregation_ is taken into consideration, to ensure minimal false positives. Finally, the _priority_ for the alert generated needs to be added to match with the risk/threat level of that event.
5. **Documentation**: _Standard Operating Procedures (SOP)_ outline the process that an analyst must follow when an alert is generated. It standardizes procedures for detecting, mitigating, and responding to cyber incidents, ensuring that all team members know their roles and responsibilities in protecting organizational assets.
6. **Onboarding**: Before deploying the use case on the production environment, it needs to first be tested on the development stage.
7. **Fine-tuning**: The use case needs to be continuously updated and fine tuned to ensure that it is alerting only on the needed events, and to reduce the volume of false positives.

To ensure the use case is working properly, these two quantitative measures will assess the use case's effectiveness:

- **Time to Detection (TTD)**
- **Time to Response (TTR)**

> The use case needs to be mapped to the [[MITRE ATT&CK Framework]] to map with known TTPs.

---

### Incident Response

The use cases developed produce alerts, and these alerts can be aggregated into incidents if needed.
- Therefore, an _incident response plan (IRP)_ needs to be set up for managing the alerts and to address the true positive incidents.

> SLAs and OLAs need to be created between teams to handle alerts and to follow the IRP.

---