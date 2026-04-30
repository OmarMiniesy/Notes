### General Notes

Digital transformation results in:
- Increasing data volumes.
- Increasing data complexity.

There are several categories of tools used in the market for data management:

![[Data Management.png]]

- *Agents & sources*: Content is sent from *sources* and collected by *agents*.
- *Pipeline & Integration*: Connect and manipulate data as it moves between sources.
- *Data Lakes*: Centralized place to store structured and unstructured data. Faces challenges in usage based on different tiers and governance.
- *Search*: Popular in security and IT as they let teams explore data quickly.

Tool Sprawl is when many tools are used and each tool needs to obtain data in its own specific format. This creates N×M integration complexity — every new tool requires new agents, new configurations, and new data pipelines for each source. The result is large configurations, excessive data volume duplication, inconsistent data across tools, and agents deployed everywhere. It increases cost and makes governance nearly impossible.

A Data Processing Engine gives centralized control over data both at rest and in motion, acting as a single plane to route, reduce, and enrich data before it reaches downstream tools.

---
### Dealing With Data

- Too many tools and techniques create vendor lock-in and data silos.
- Storing data in various places and lakes with different tiers causes access issues, data fragmentation, and data inconsistency.
- Data spread across different tools and locations is difficult to govern and potentially vulnerable to compromise.
- Different stakeholders need data from different places, and centralizing that data is challenging given the variety of tools, storage locations, and formats.

Data Management is defined in the DAMA (Data Management Association) framework — the industry standard body for data management best practices. The aspects most relevant for IT and Security are:
- **Data Quality**: Ensures data is easier to analyze and quicker to process.
	- Accuracy and integrity.
	- Completeness.
	- Consistency, Validity, Uniqueness, and Timeliness.
- **Metadata**: Data about data, used to enrich, contextualize, and correlate the data.
	- Descriptive metadata: Information about the data for discovery and identification — time, location, source, etc.
	- Structural metadata: Used for correlating data across different sources or systems.
	- Admin metadata: Used for management of resources, compliance, access control, and ownership.

Ensuring Data Quality:
- **Data Profiling**: Assessment of existing data assets to understand quality and structure.
- **Data Standardization**: Defining what schemas and data profiles should look like across the organization.
- **Geocoding**: Enriching data with location-based connections and context.
- **Data Monitoring**: Frequent checks to ensure data does not drift from expected values over time.
- **Timeframe**: Understanding the time window this data applies to and its validity period.

---
### Key Terms

Data Management Strategy
- A comprehensive plan for how an organization will manage and utilize data assets to achieve its objectives.
- Should include delivery of data into tiered storage based on timeliness requirements and retention requirements.
- Should not be fixed — strategies must remain adaptable as data volumes and business needs evolve.

4 V's: Characteristics of data
- **Volume**: The amount of data being collected and generated.
- **Variety**: The different sources and types of data — structured, semi-structured, and unstructured.
- **Value**: A measure of how useful the data is. Value can fluctuate — data that is critical during an incident may have low routine value.
- **Velocity**: The speed at which data is generated and must be processed. Especially relevant for real-time streaming scenarios where delays in processing reduce data usefulness.

Telemetry Data:
- Data about a system's performance, health, and usage for monitoring and analysis.
- Includes network traffic, system utilization, and resource consumption metrics.

O11y Data (Observability):
- Includes additional information about a system's internal state and behavior.
- Provides a holistic view of how systems interact with each other — going beyond raw metrics to understand *why* a system behaves a certain way.

Security Data:
- Information related to security events, threat indicators, and compliance requirements.
- Sources include [[Firewall]] logs, [[IDS & IPS]] alerts, endpoint telemetry, and [[Network Analysis|network captures]].
- Feeds into [[SIEM]] and UEBA platforms for threat detection and investigation.

Data Optimization is the process of improving the quality, efficiency, and effectiveness of data by enhancing:
- **Collection**: Ensuring that data is collected from relevant sources in a timely and accurate manner.
- **Reduction**: The process of filtering, aggregating, and summarizing data to retain only what is necessary — reduces storage costs and noise.
- **Shaping**: The transformation and restructuring of data to make it more accessible and usable for downstream consumers.
- **Enrichment**: Enhancing data with context, metadata, and external sources to improve its value and usefulness.

> Optimization helps make better decisions, achieve business objectives, and leverage data as a strategic asset. In [[Supporting Tech]], each of these steps maps to a specific [[Stream]] pipeline function.

MELT — the four pillars of telemetry data:
- **Metrics**: Numeric representations of data measured over a defined interval of time (e.g., CPU usage at 5-second intervals). Aggregated and summarized — least verbose.
- **Events**: Discrete occurrences observable at a specific point in time, represented as key-value pairs (e.g., a user login, a service restart).
- **Logs**: Detailed, system-generated records describing what happened during or around an event. Most verbose — contains structured fields plus a free-form log message in any format. See [[Logs]] and [[Log Analysis]].
- **Traces**: A record of the path taken by a transaction across an application. Connects individual spans across services to allow profiling and performance analysis of distributed systems.

Common Solutions used in data management:
- **Data Lake**: Centralized repository that allows organizations to store data at different cost tiers in different formats.
- **Agents**: Software deployed on infrastructure nodes that collect information and forward or process it.
- **Object Storage**: Manages data as objects — cheap, scalable, ideal for long-term retention (e.g., [[Simple Storage Service (S3)|AWS S3]]).
- **Time Series**: Sequences of data points collected over time, optimized for range queries and aggregations.
- **Indexed Log Analytics**: Search engines optimized for investigations and full-text log searches.
- **SIEM/UEBA**: Used for correlating security incidents and protecting against cyber threats — see [[SIEM]].

---
### Lifecycle

Data is separated into phases as it meets different requirements. Each phase maps directly to a [[Cribl Products|Cribl product]]:

- **Discovery**: Done by agents at the location where data is collected. Performs monitoring, collection, and forwarding of the data. → *Cribl Edge*
- **Processing**: Done by a pipeline to transform, secure, enrich, and route data to the needed destination — see [[Supporting Tech]] for the functions used. → *[[Stream]]*
- **Storing**: A database or object store to retain and manage the data long-term. → *Cribl Lake*
- **Exploring**: The ability to query, explore, and visualize data for different analytical and operational needs. → *Cribl Search*

---
