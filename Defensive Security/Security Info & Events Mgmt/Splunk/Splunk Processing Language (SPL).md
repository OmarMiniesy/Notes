#### General Notes

The query language by [[Splunk]], allowing users to search, filter, and manipulate the indexed data.
- Check out [[Handling Data]].

> Searching queries can be concatenated together using the pipe `|`, similar to *KQL (Kusto Query Language)*.

---
##### Searching

To search for events, the `search` keyword is used. However, the search command is usually implicit and is not written out.
- This is done using the *Searching & Reporting* [[Splunk Application]].

To use SPL to search for data, an **index** must be specified. 
- This can be done using the `index` keyword, and specifying the name of that index between quotes.
- The `main` index is used by default and does not need to be specified.

Boolean operators can be used for more specific queries: `NOT, AND, OR`.
- Wildcards can be used to replace any number of characters: `*`.

This searches in the `main` index for any event that includes the keywords specified in the end.
```SPL
index="main" "data-to-search-for"
```
- Writing text without specifying a field will query all the fields. This is case insensitive.

A *macro* is a placeholder for a more complex search query that can take arguments if variables are needed.
- Macros are created from the settings, and they referenced using the backticks.
```SPL
`macro-name`
```

##### Fields and Comparison Operators

Users can manually define fields to search for, and Splunk can automatically identify data fields like:
- `source`
- `sourcetype`
- `host`
- `eventcode`

There are some default fields that Splunk attaches to all events:
- `source`
- `sourcetype`
- `host`
- `_time`
- `index`

> Fields can also be called [Indexed Fields](https://docs.splunk.com/Splexicon:Indexedfield), and those are stored in Splunk's inverted index, meaning that searches on these fields are faster and consume less resources. There are a set of automatically indexed fields, like `_time`, `host`, `source`, `sourcetype`, and `_raw`.

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

The `dc` function can be used to count the unique number of a certain field.
```SPL
index=main source="WinEventLog:Security" EventCode=4625
| stats values(user) as Users, dc(user) as dc_user by src
```
- This groups by the `src` host the usernames and the distinct count of usernames tried.

> `rex` command can be used to create fields using [[Regular Expressions]]. [Guide on Splunk docs](https://docs.splunk.com/Documentation/Splunk/9.4.2/SearchReference/Rex).

The `stats` command can be used to perform statistical operations, such as counting.
```SPL
index="main" sourcetype="WinEventLog:Sysmon" EventCode=3 | stats count by _time, Image
```
- This will return an extra column called `count`, that counts the number of unique combinations of `_time` and `Image`.
- When using the `stats` with `values`, use the `as` to rename the column to be used in later filters using `where` if they are going to be used again.

> The `chart` command can be used to visualize statistical operations. Instead of `stats`, use `chart`.

---

