### General Notes

This is a solution that allows storing data to be used to replay it later.
- Put in cheap storage.
- Saves money on retention.
- Keeps the data around for longer

To replay data, we can point Cribl Stream to the storage location to replay the data.
- Object retrieval and unpacking is resource heavy.
- Should use searching against fields and not the `raw` field to improve performance.

Better practices:
- Use compatible storage classes.
	- Does not support S3 Glacier, S3 Deep Glacier
	- Supports S3 Glacier Instant
- Use also a filename filter to improve data quality and latency.
- Adjust the path field to optimize performance by placing the time in the field name.
- Check the API limits for object storage destination
- Check the Event Breakers Ruleset.
- Add a field to identify events that have been replayed.
- Test the replay in preview mode.

---
