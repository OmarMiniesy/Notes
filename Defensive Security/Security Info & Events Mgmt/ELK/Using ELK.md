### Discover Tab

The *discover tab* in [[ELK - Elasticsearch, Kibana, & Logstash#Kibana|Kibana]] is the main interface that shows:
- A list of *logs*, also known as a document that contains information about a single event. Opening an event and adding one of the fields to a table adds a column next to the document column with the value of that column. Can be used for easier filtering and summarization.
- A list of *fields* that are present inside the event logs. These fields can be sorted through using a search function, and each field shows the top 5 most values found in the event logs.
- An *index pattern* selector that can be used to choose the data store to operate on.
- The *search bar* where [[Kibana Query Language]] queries can be written. 
- The *add filter* option below applies filters on the fields instead of typing using KQL in the search bar.
- A *time filter* setting to limit and filter the logs we are searching on. 
- A *time interval* graph that shows the distribution of the events over the time duration picked.

---
### Visualizations

To create data visualizations like tables, pie charts, bar charts, ...
- Clicking on any field in the *discover tab* and then clicking on visualization will spawn the visualization tab.
- Dragging fields from the left to the visualization will start creating correlations between these fields.

---
### Dashboards

These can be used to create pages with saved visualizations and searches.

---
