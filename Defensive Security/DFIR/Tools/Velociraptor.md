### General Notes

This is an [[Endpoint Detection and Response (EDR)]] tool that is used to gather host-based related forensic evidence using the *VQL, Velociraptor Query Language*.
- Velociraptor can also execute *Hunts* to gather artifacts.
- Can be used to dump the memory of an endpoint remotely.
- [Velociraptor Documentation](https://docs.velociraptor.app/docs/)

Artifact collection is the way velociraptor works.
- By choosing an artifact to search for whatever is needed and configuring it.
- Then performing queries on the output.

> Velociraptor can utilize [[KAPE]] *target* files to collect evidence.

---
### Clients

When a client is added, we can see this data from the home page:
- *Online State*: If it is green, then the endpoint is live. If it is yellow, then server hasn't received comms for 24 hours. If it is red then more than 24 hours have passed since the last communication.
- *Client ID*: A unique ID assigned to the client by the server. Client IDs always start with the letter C.
- *Hostname*: The hostname used by the client to be identified by the server. Hostnames can change.
- *OS Version*: Operating system of the client.
- *Labels*: Can be used to identify client groups.

Clicking on a client, we see the *overview* tab which has extra details about the client and the agent running on the client.
- There is also the *VQL Drilldown* tab with information about CPU & memory usage, and the [[Active Directory]] domain of that client.
- The *Shell* tab is used to execute commands on the remote machine. Launching a command then clicking on the eye icon shows the output of that command.
- The *Collected* tab showcases information collected for that client. This includes any commands run or any interactions with the file system. From here we can specify what files to collect from the client to perform an investigation. We choose the targets we want to collect from the *select artifact*, or `+` button.
- The *Interrogate* tab queries the client for some basic information.
- The *VFS* tab, or the Virtual File System is a tool to inspect the client's filesystem and fetch files. For Windows, it can inspect the [[File System]], NTFS, the [[Windows Registry]], and the artifacts collected from the client. Can view at the bottom the text, hex, and even download the file.

---
### VQL

The [documentation](https://docs.velociraptor.app/docs/vql/) is a good source to understand VQL.
- VQL follows a similar structure to SQL.
- VQL can be run from *notebooks*.

> *Artifacts* allow us to package one or more VQL queries and related data into a human-readable YAML file which is stored within the Velociraptor server’s datastore. The [artifact exchange](https://docs.velociraptor.app/exchange/) has community artifacts.

The fields contained in an artifact are:
1. **Name**: The artifact contains a name. By convention the name is segmented by dots in a hierarchy. The Name appears in the GUI and can be searched on.
2. **Description**: Artifacts contain a human readable description. The description field is also searchable in the GUI and so should contain relevant keywords that make the artifact more discoverable.
3. **Type**: The type of the Artifact. Since Velociraptor uses VQL in many different contexts, the type of the artifact hints to the GUI where the artifact is meant to run. For example, a `CLIENT` artifact is meant to be run on the endpoint, while a `SERVER` artifact is meant to be run on the server. The artifact type is only relevant for the GUI.
4. **Parameters**: An artifact may declare parameters, in which case they may be set by the GUI user to customize the artifact collection.
5. **Sources**: The artifact may define a number of VQL sources to generate result tables. Each source generates a single table. If more than one source is given, they must all have unique names.
6. **Precondition**: A source may define a precondition query. This query will be run prior to collecting the source. If it returns no rows then the collection will be skipped. Preconditions make it safe to collect artifacts from all hosts (e.g. in a hunt), and ensure that only artifacts that make sense to collect are actually run.
7. **Query**: The query that will be used to collect that source. Note that since each source **must** produce a single table, the query should have exactly one `SELECT` clause and it must be at the end of the query potentially following any `LET` queries.

---
