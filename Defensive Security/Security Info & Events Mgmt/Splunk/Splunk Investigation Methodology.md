### General Notes

This is my methodology for investigating on a [[SIEM]] using [[Splunk]] and the [[Splunk Processing Language (SPL)]].

---
### Understanding the Data

##### Understand the type of data present in the index

This outputs all the `sourcetype` present, along with the count of events present in each.
- This can be used to understand the type of data present in the index and its quantities.
- This helps in knowing where to look for and search for specific data.

``` 
index=main
| stats count by sourcetype
```

---
### Investigating [[Sysmon]]

Look at the Event Codes present:
```
sourcetype = sysmon
| stats count by EventCode
```
- Understand the data present.
- Go through event codes based on need.


To look at all the values of something and group them by something else:
```
| stats values(something), count by (something-else)
```
- For ex, to look at all the processes and group them by their parent process.


##### `EventCode 1` - Process Creation

To have a holistic view when analyzing processes:
- Can also include the `ParentProcessId` for correlation and mapping
```
| table _time Image ParentImage CommandLine User IntegrityLevel ProcessId
```

To get a count of the parent/process relationships:
```
| stats count by ParentImage, Image
```

Understand what was executed, see rare events, remove noisy processes.
```
| stats count by Image
| sort - count
```

Understand parent-child process relationships. Check out known bad, or weird looking events.
```
| stats count by ParentImage Image
| sort - count
```

---
