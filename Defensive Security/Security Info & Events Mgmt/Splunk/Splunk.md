### General Notes

This is a data analytics software known for its ability ingest, index, analyze, and visualize large amounts of data.
- This makes it very useful for several use cases, such as a [[SIEM]], where it allows for data analysis, monitoring, incident response, and [[Threat Hunting]].
###### Datasets
Links to datasets that can be used to learn Splunk.
- [BOTS](https://github.com/splunk/botsv3)
- [nginx_json_logs](https://raw.githubusercontent.com/elastic/examples/refs/heads/master/Common%20Data%20Formats/nginx_json_logs/nginx_json_logs)

---
### Splunk Architecture & Components

Splunk has several layers that work together to collect, index, search, analyze, and visualize data.
- There are *Forwarders*, *Indexers*, *Search Heads*, *Cluster Master*, *Deployment Server*, and *License Master* in the architecture.
- Splunk has key components that make using Splunk easier and more efficient, like the *Splunk Processing Language (SPL)*, *apps and add-ons*, and *knowledge objects*. 

##### Architecture

**Forwarders** are responsible for collecting the data by collecting machine data from various sources and sending them to the *indexers*. There are several types of forwarders:
- *Universal Forwarder*: Lightweight agent that collects data and forwards it to Splunk without any pre-processing. They are software packages that can be installed on remote hosts, and they do not affect network or host performance.
- *Heavy Forwarder*: This is also an agent that collects data from remote sources that have intensive data aggregation taking place, like [[Firewall]]s or routers. They have the ability to parse the collected data on the remote host and route them to different recipients in the Splunk architecture based on different criteria. They also have the ability to *index* data locally while forwarding them to an *indexer*.
	- They act as data collection nodes to collect data from remote sources using [[Application Programming Interface (API)]]s and processing it.
- *HTTP Event Collectors (HECs)* can collect data from applications using token-based `JSON` or raw APIs and sends it directly to the *Indexer* for further processing.

**Indexers**: These receive data from the *forwarders*, organize it, and then store it in indexes. Indexing is the process of storing data in an optimized format for efficient searching.
- The indexed data is stored in buckets, which are a storage format that organize the data by time and age. Once the data is indexed, it can become searchable using *Search Heads*.

**Search Heads**: This is the interface between the user and the stored data, which is done by running the search queries and returning the responses.
- Search heads process a search request by sending it to the appropriate *indexer* to retrieve the necessary data.
- The search head aggregates the retrieved data, processes it, and then can output it in several methods like dashboards, reports, or visualizations.
- Search heads can distribute the searching over multiple indexers for efficiency with larger datasets.
- Search heads can be clustered together for load balancing and redundancy in case of the failure of one search head.

**Deployment Server**: It manages the configuration for forwarders, distributing apps and updates.

**Cluster Master**: The cluster master coordinates the activities of indexers in a clustered environment, ensuring data replication and search affinity.

**License Master**: It manages the licensing details of the Splunk platform.

##### Key Components

**[[Splunk Processing Language (SPL)]]**: The query language for Splunk, allowing users to search, filter, and manipulate the indexed data.

**Knowledge Objects**: These include fields, tags, event types, lookups, macros, data models, and alerts that enhance the data in Splunk, making it easier to search and analyze.
- *Macros*: These are predefined search strings or queries that can be reused, it is like a shortcut to be used for a more complex query, and arguments can be passed if variables are needed.

**Apps and Add-ons**: Apps can provide specific functionalities within Splunk, while add-ons can extend current capabilities or integrations.
- Apps can be found on [Splunkbase](https://splunkbase.splunk.com/), and they provide additional functionalities and pre-configured solutions.
- Add-ons serve as an abstraction layer for data collection methods. They often include relevant field extractions, allowing for schema-on-the-fly functionality.

---
