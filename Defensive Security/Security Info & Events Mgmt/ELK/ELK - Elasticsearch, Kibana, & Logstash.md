### The Elastic Stalk

This a collection of 3 applications that work together to offer search and visualization capabilities of log files.
- **Kibana** : Visualization
- **Elasticsearch** : Searching and analyzing
- **Logstash** : Ingesting (storing/collecting)

**Beats** are an another component of the stack.
- These are used as remote shippers of data.
- They are installed on remote machines and are used to send data to **Logstash** or _Elasticsearch_.
###### Elasticsearch
This is a JSON based search engine.
- Handles indexing, storing, and querying of data.
- Allows for complex querying on log files stored.
###### Logstash
This is responsible for collecting, transforming, and transporting log data files.
- It can obtain data from various resources and normalize them into a standard format.
- It works following 3 functions.

1. **Processing Input**: Logstash first works by ingesting log data records from different locations and then converting them to a format that machines can understand. This can be done using [input plugins](https://www.elastic.co/guide/en/logstash/8.1/input-plugins.html).
2. **Transforming and Enriching Log Records**: A log can be formatted by modifying its structure or content to standardize it into a normalized format. These logs can also be enriched, or have more content added to it to make it more meaningful and actionable. This can be done using [filter plugins](https://www.elastic.co/guide/en/logstash/8.1/filter-plugins.html).
3. **Send to Elasticsearch**: These logs are then sent to Elasticsearch using output plugins. This can be done using [output plugins](https://www.elastic.co/guide/en/logstash/8.1/output-plugins.html).
###### Kibana
This is the visualization tool for the documents stored in Elasticsearch.
- The data stored can be viewed.
- Queries can be executed on Kibana, and the results are presented as output there.
- It utilizes charts, tables, and dashboards.

> Queries are performed using KQL, [[Kibana Query Language]], or Lucene.

---
