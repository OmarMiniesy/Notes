### General Notes

Replay allows data to be selectively ingested and re-ingested into systems of analysis.
- Data is stored cheaply and replayed later when needed.
- Data is placed in low-cost object storage (e.g., [[Simple Storage Service (S3)|AWS S3]]).
- It is then retrieved and allows searching on this data, or can be routed to any [[Destinations]].

> Reduces retention costs while keeping data accessible for historical analysis.

To replay data, point Cribl Stream at the storage location containing the archived data.
- Object retrieval and unpacking are resource-intensive operations.
- Search against indexed fields rather than the `_raw` field to improve performance.
- The leader picks one node to perform the lookup and find the data, then the entire worker group is used to retrieve and re-ingest the found data.

Better practices:
- Use compatible object storage classes.
	- Does not support S3 Glacier, S3 Deep Glacier
	- Supports S3 Glacier Instant
	- Use object stores because they are cheaper, easier for high volumes of data to search, retrieve, and handle its metadata.
- Use also a filename filter to improve data quality and latency.
- Adjust the path field to optimize performance by placing the time in the field name.
- Check the API limits for object storage destination
- Check the Event Breakers Ruleset — see [[Supporting Tech]] for how event breakers work.
- Add a field to identify events that have been replayed.
- Test the replay in preview mode.
- Use a dedicated Worker Group because it is intensive and this can be placed closer to the location of the data.

##### To use the Replayed Data

Can use the following filter expression to capture the replayed data:
```
__inputId.includes('Replay')
```
- Where `Replay` here is the name of the collector that was used. Check out [[#The Replay Source - The Collector]].

Moreover, when searching, it is better to search using the partitions not the data of the actual events.

---
### Defining the Destination

The Destination that will receive the replayed data needs to be configured.
- The bucket name can be a constant or a JS expression that will be evaluated only on initialization. [[Cribl/Cribl Stream/Events|Events]] level variables cannot be used here, as the value of the name expression is only evaluated once at initialization time.
- To use event level variables, they can be used in the Partitioning Expression field because this is evaluated for each file. It is date based by default, and it is used to partition the files and organize them.
	- Stream will check for the `__partition` field value if its present in the event. If not, it will default to the root directory of the Output and Staging location.
- The file name prefix expression must be a JS expression that evaluates to a constant.

It is good practice to create multiple replays with each different prefixes and partitioning expressions to make it easier to search the data.

> The partition information in the destination should be the same as the partition information on the collector for the data to be collected.

---
### The Replay Source - The Collector

Pointing Cribl to the source of data that will be used to replay the data.
- We can use the name of the file, or the file path, and filter on it. This is used to reduce the workload of finding the necessary data.
- We can also filter on the necessary data using its fields. Prioritize other fields over the `_raw` field.

> Object retrieval and unpacking is process heavy.

[[Stream]] can use *event breaker rulesets*.
- This is used to convert the log data from its stored format to readable and structured data.
- There are Cribl rulesets and custom rulesets we can create.
- Check out [[Supporting Tech]].

> Good practice to add a field `__replay` to `true` to all events that have been replayed, which can be use for filtering in [[Routes]] and pipelines.

It is important to actually **run** the replay process.

---
