### General Notes

All data processing is based on discrete entities called events.
- This is a collection of key-value pairs, called fields.

Some fields can be added by Cribl internally.
- These begin with a double underscore (`__`).
- They are not forwarded to the destination — they are used only within [[Stream]] during processing.

If an event cannot be JSON-parsed, its content will be placed in the `_raw` field.
- If the timestamp is not configured, the current time will be assigned to a field called `_time`. Using UNIX epoch format.

---

