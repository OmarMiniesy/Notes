### General Notes

To properly use a [[SIEM]] like [[Splunk]], the available data sources sending data, the data that is provided, and the data fields themselves should be well understood.
- We can do that using the *Search & Reporting Application* and write queries using [[Splunk Processing Language (SPL)]].
- We can also utilize the user interface. 

---
### Using Search & Reporting Application with SPL

> Before running any of the commands using [[Splunk Processing Language (SPL)]], first select a suitable time range in the time picker of the application.

##### Understanding Indexes

Splunk digests a large source information from various data sources, and each data source formats the data differently.
- These are called different source types, or *indexes* available. To view them, use this command:
- The default index is Splunk is `defaultdb`
```SPL
| eventcount summarize=false index=* | table index
```
- The `eventcount` is used to count events in all the indexes and then `summarize=false` shows the count of events for each index.

We can also use the `metadata` command that gives statistics about the specified entity, which can be `sourcetypes`, `sources`, `hosts`. 
```SPL
| metadata type=<sourcetypes|sources|hosts> index=*
```

##### Listing `SourceType`s

We can also view the different `sourcetype`s using this command:
```SPL
index="main" | stats count by sourcetype
```
##### Understanding a `SourceType`

Once we identify a `sourcetype` of interest, we can see the raw textual event data of that source type.
```SPL
sourcetype="WinEventLog:Security" | table _raw
```
- We can choose a set of fields to display only, using the `fields` command and then applying the `table` command to see it in a table format.

To see only the list of field names, without the actual data in the fields, we can use the `fieldsummary` command.
- This works on the selected time range.
```SPL
sourcetype="WinEventLog:Security" | fieldsummary
```
This returns the following information for each field:
- `field`: The name of the field.
- `count`: The number of events that contain the field.
- `distinct_count`: The number of distinct values in the field.
- `is_exact`: Whether the count is exact or estimated.
- `max`: The maximum value of the field.
- `mean`: The mean value of the field.
- `min`: The minimum value of the field.
- `numeric_count`: The number of numeric values in the field.
- `stdev`: The standard deviation of the field.
- `values`: Sample values of the field.

To know how events are distributed over time, we can use the `bucket` command to group the events based on the `_time` field into 1-day buckets. 
- The `stats` command then counts the number of events for each day (`_time`), `index`, and `sourcetype`. 
- Lastly, the `sort` command sorts the result in descending order of `_time`.
```SPL
index=* sourcetype=* | bucket _time span=1d | stats count by _time, index, sourcetype | sort - _time
```

The `rare` command can be used to identify uncommon event types. This finds the rarest combinations of `index` and `sourcetype`.
```SPL
index=* sourcetype=* | rare limit=10 index,sourcetype
```

We can also use the `sistats` command to explore event diversity. 
```SPL
index=* | sistats count by index, sourcetype, source, host
```
- This command counts the number of events per `index`, `sourcetype`, `source`, and `host`, which can provide us a clear picture of the diversity and distribution of our data.

---
