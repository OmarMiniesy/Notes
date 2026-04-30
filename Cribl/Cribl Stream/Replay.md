### General Notes

Replay allows data to be stored cheaply and replayed later when needed.
- Data is placed in low-cost object storage (e.g., [[Simple Storage Service (S3)|AWS S3]]).
- Reduces retention costs while keeping data accessible for historical analysis.

To replay data, point Cribl Stream at the storage location containing the archived data.
- Object retrieval and unpacking are resource-intensive operations.
- Search against indexed fields rather than the `_raw` field to improve performance.

Better practices:
- Use compatible storage classes.
	- Does not support S3 Glacier, S3 Deep Glacier
	- Supports S3 Glacier Instant
- Use also a filename filter to improve data quality and latency.
- Adjust the path field to optimize performance by placing the time in the field name.
- Check the API limits for object storage destination
- Check the Event Breakers Ruleset — see [[Supporting Tech]] for how event breakers work.
- Add a field to identify events that have been replayed.
- Test the replay in preview mode.

---
