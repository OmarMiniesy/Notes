### General Notes

*Malware Information Sharing Platform*, or [MISP](https://github.com/misp), is an open source [[Cyber Threat Intelligence]] platform.
- Allows for the collection, storage, and distribution of threat intel and IOCs.
- Allows for the distribution of threat information to other security tools like [[SIEM]], [[IDS & IPS]].

> [MISP Book](https://www.circl.lu/doc/misp/)

MISP provides these functionalities:
- *IOC database*: Storage of all types of threat intelligence information.
- *Correlation*: Relationships between attributes and indicators from [[Malware]], attack campaigns, or analysis.
- *Data Sharing*: Sharing of information amongst MISP instances and using different models of distribution governing who can access which data, and to what degree.
- *Import & Export*: The import and export of events in different formats to different tools and security endpoints.

MISP uses this terminology:
- *Events* are contextually linked pieces of information. Events can include any of the below.
- *Attributes* are individual data points that can be associated in an event.
- *Objects* are custom groupings of attributes to define a specific piece of information.
- *Object References* are relationships between objects.
- *Sightings* are time specific occurrences of when an attribute was detected.
- *Tags* are labels that can be attached to events and attributes.
- *Taxonomies* are classification libraries to organize and classify information.
- *Galaxies* are contextual tags that describe what the event or attribute is related to. Used for standardization, searching, enrichment, and correlation.
- *Indicators* are pieces of information that can detect malicious activity.

---
