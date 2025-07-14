### General Notes

This is an application on Windows machines that allows to view the logs on the system.
- Information about the event that is logged is displayed includes [[Windows Events Log#Event Entry|Event Entry Information]].
- Can be opened by typing `eventvwr.msc` in the command prompt.

It can integrate with other tools to view logs, such as [[Sysmon]] and [[SilkETW]].
- It can open and display `.evtx` log files from the *Saved Logs* section.

---
### Using Event Viewer

There are 3 panes for event viewer:
- *Left Pane*: This is a hierarchical view of the event log providers.
- *Middle Pane*: This is the display for the chosen provider to show the events. It also shows a general overview, summaries, and information about the provider.
- *Right Pane*: This is the actions pane, where filtering can take place on the logs in the middle pane.

The left pane includes the:
- *Windows Logs*, which contain the logs from the [[Windows Events Log]] and all their types.
- *Applications and Services Logs*, which has the logs from a large amount of applications and services on the machine, including *Microsoft* services and applications. 

Choosing a provider and then clicking on *properties* in the actions pane shows a lot of information about that log source:
- log location
- log size
- dates of creation, modification, and access
- maximum log size and actions to be taken then.
- The *clear log* button.

The middle pane showcases the actual events, with their level, date and time, their source, the Event ID, and the event category.
- The bottom half shows the details about the chosen event. The general view renders the data, while the detailed view showcases it in greater detail and can be displayed in XML format.

---
### [[XML]] Queries

Advanced filtering using [[XML]] can be performed by choosing *filter current log* then *xml* then *edit query manually*.
- This [article](https://techcommunity.microsoft.com/blog/askds/advanced-xml-filtering-in-the-windows-event-viewer/399761) has advanced filtering explained.

- To filter for DLL hijack attacks:
```
*[System[(EventID=7)]] and *[EventData[Data[@Name='Signed'] != 'true']]
```

---
