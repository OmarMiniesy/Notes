#### General Notes

The query language by [[Splunk]], allowing users to search, filter, and manipulate the indexed data.

> Searching queries can be concatenated together using the pipe `|`, similar to *KQL (Kusto Query Language)*.

---
##### Searching

To search for events, the `search` keyword is used. However, the search command is usually implicit and is not written out. 

To use SPL to search for data, an **index** must be specified. 
- This can be done using the `index` keyword, and specifying the name of that index between quotes.

Boolean operators can be used for more specific queries: `not, and, or`.
- Wildcards can be used to replace any number of characters: `*`.

This searches in the `main` index for any event that includes the keywords specified in the end.
```SPL
index="main" "data-to-search-for"
```

##### Fields and Comparison Operators

Users can manually define fields to search for, and Splunk can automatically identify data fields like:
- `source`
- `sourcetype`
- `host`
- `eventcode`

Fields can be used with comparison operators for more precise searching:
- `=, !=, <, >, <=, >=`.

This searches in the `main` index for events that do not have an `eventcode` equal to 1.
```SPL
index="main" EventCode!=1
```

##### Search Display

The `fields` command can be used to specify which fields to be excluded from the output results.

This command searches in the `main` index only for [[Sysmon]] event logs, and from those events it extracts those with `eventcode` equals to 1. It then displays all fields normally but removes the output field `User`.
```SPL
index="main" sourcetype="WinEventLog:Sysmon" EventCode=1 | fields - User
```

Some other commands to modify the output shape:
- The `table` command is used to present the output in a tabular format.
```SPL
index="main" sourcetype="WinEventLog:Sysmon" EventCode=1 | table _time, host, Image
```
- The `rename` command is used to rename a field in the search results.
```SPL
index="main" sourcetype="WinEventLog:Sysmon" EventCode=1 | rename Image as Process
```

##### Search Output

The `dedup` command can be used to remove duplicate entries based on a given field.
```SPL
index="main" EventCode=1 | dedup Image
```

The `sort` command is used to sort according to a field.
```SPL
index="main" sourcetype="WinEventLog:Sysmon" EventCode=1 | sort - _time
```
- This works in descending order, that is, the most recent events are shown first.

The `eval` command can be used to create or redefine fields.
```SPL
index="main" sourcetype="WinEventLog:Sysmon" EventCode=1 | eval Process_Path=lower(Image)
```
- This creates a new field which has the lower-case version of `Image`.

> `rex` command can be used to create fields using [[Regular Expressions]].

The `stats` command can be used to perform statistical operations, such as counting.
```SPL
index="main" sourcetype="WinEventLog:Sysmon" EventCode=3 | stats count by _time, Image
```
- This will return an extra column called `count`, that counts the number of unique combinations of `_time` and `Image`.

> The `chart` command can be used to visualize statistical operations. Instead of `stats`, use `chart`.


---

