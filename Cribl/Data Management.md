### General Notes

Digital transformation results in:
- Increasing data volumes
- Increasing data complexity.

There are several types of tools used in the market for data management, with different types.

![[Data Management.png]]

- *Agents & sources*: Content is sent from *sources* and collected by *agents*.
- *Pipeline & Integration*: Connect and manipulate data as it moves between sources.
- *Data Lakes*: Centralized place to store structured and unstructured data. Faces challenges in using based on different tiers and governance.
- *Search*: Popular in security and IT as they let teams explore data quickly.

Tool Sprawl is when many tools are used and each tool needs to obtain data in a format, resulting in large configurations and large data volume and many agents everywhere.

Data Processing Engine gives control over data at rest and in motion.

---
### Dealing With Data

- Too many tools and techniques, creating vendor lock in and data silos.
- Storing data in various places, lakes, with different tiers and access issues, as well as data fragmentation, data inconsistency.
- Data in different tools and locations, results in data being compromised.
- Different stakeholders need data from different places, and this data needs to be centralized somewhere to be used, which is tough to do given many tools and storage locations and formats.

Data Management is defined in the DAMA framework, but whats imp for IT and SEC in this framework are:
- Data Quality: easier to analyze and quicker to process.
	- Accuracy and integrity.
	- Completeness.
	- Consistency & Validity & Uniqueness & Timeliness.
- Metadata: Data about data to enrich, contextualize, correlate the data.
	- Descirptive meta data: information about the data for disocvery and identification. Time, location, ..
	- STructural meta data: used for correlating data. 
	- ADmin meta data: used for management of resources, compliance, access, ownership


Ensuring Data Quality:
- Data Profiling: Assessment of the assets
- Data Standardization: What type of schemas and profiles to create
- Geocoding: Connections based on location. 
- Data monitoring: Frequent checks so that data is not subject to time drift.
- Timeframe: The timeframe this data applies to. 

---
### Key Terms

Data Management Strategy
- Comprehensive plan how an org will manage and utilize data assets to achieve objectives.
- SHould include delivery of data into tiered storage based on timeliness requirements, and retention rqeuirements.
- These should not be fixed and remain adaptable.

3 V's : Characteristics of data
- Volume: The amount of data being collected and generated.
- Variety: The different sources and types of data. (Structured, semi structured, and unstrcutred data)
- Value: The measure of how valuable the data. The value of the data might not be high at all time, depending on the current situation.

Telemetry Data:
- Data about a system's perforamnce, health, and usage for monitoring and analysis.
- This includes entwork traffic, system utiliziation.

O11y Data (Observability):
- Includes additional info about system internal state and behavior.
- PRovides hollisitic view of how systems interaact with each other.

Security Data: 
- Info related to security events and compliance requirements.

Data Optimization is the process of improving quality, efficiency, and effectiveness of data by enhancing:
- Collection: ensuring that data is collected from relevant sources in timely and accurate manner
- Reduction: The process of diltering, aggregating, and summarizing data to filter on the necessary data.
- Shaping: The transformation and structuring of data to make it more accessible and structurable for other usages.
- Enrichment: Enhanacing with context, metadata, and other sources to improve value and usefulness.

> Optimization helps make better decisions, achieve buesinsess objectives, and leverage data as a strategic asset.

MELT for telemetry data.
- Metrics: numeric represetnations of data measured over a certain interval of time.
- Events: Anything that we can observe happening at any point of time. This is a set of key value pairs describing something that occurred.
- Logs: Detailed information that are system generated that describe what is going on during the event. Contains a set of standard information in addition to the log message itself which can be in any format.
- Traces: A trace marks the path taken by a transcation within an application. A trace allows profiling and observing information. A trace shows how different parts of an application perform their part.

Common Solutions that are used:
- Data Lake: Centralized repo that allows orgs to store data at different costs in different formats.
- Agents: Software deployed on infrastructure node that collects information and sends it or uses it.
- Object STorage: MAnages data as objects, cheap storage long term retention.
- Time Series: Sequences of data points collected over time.
- Indexed Log Analytsics: Engines for investigations and searches.
- SIEM/UEBA: Used for security incidents and protection against cyber threats.

---
### Lifecycle

Data is separated into phases as it meets requirements.
- Discovery: Done by agents at the location where the data is to be collected. Performs monitoring collection and forwarding of the data.
- Processing: Done by pipleine to transform, secure the data, and route it to the needed place.
- Storing: database to store and manage the data.
- Exploring: ability to query, explore, and visualize the data for different needs

---
