### General Notes

This is a data collection **agent** with centralized management, deployed directly on a node to collect data from it.
- Can collect [[Logs|logs]], metrics, application data, and more.
- Edge automatically discovers and collects this data without manual configuration.
- Can also perform data exploration close to the source to determine what needs to be collected — searching directly at the node reduces unnecessary data movement.
- Edge is vendor-agnostic: any data can be collected from any source.
- Offers centralized management to control multiple agents on multiple endpoints.

Agents are used in the discovery phase of [[Data Management]], and they are used to:
- Find the files to be ingested and discover unknown files.
- Read and monitor files of different formats.
- Collect data from a variety of file formats.
- Send the collected data for processing/storing in a chosen destination.

> Having multiple agents on one endpoint to collect different types of data is tedious. Therefore, a single agent that is vendor agnostic is a better solution.

Edge nodes can be grouped into logical fleets and sub-fleets, allowing them to share configurations.
- Edge nodes can be upgraded from the management platform without touching each node individually.

![[Edge.png]]

---
### Edge Deployment

**Single Mode**: Run edge nodes on one machine without management by leader node.
**Distributed Mode**: The leader node manages the edge nodes.

The Leader node manages all the configurations for the worker nodes and the edge nodes.
- Communication with Edge nodes (fleets) takes place to inform edge nodes how to collect the data and the scheduled collection based on collector rules.
- Communication takes place through TCP [[Port]] 4200 for heartbeat metrics and notifications to edge nodes.
- [[HTTP]] on port 4200 is used to download configuration bundles.
- The leader node's resources should be scaled up to match the number of managed nodes and the volume of configuration activity.

> The *leader node* manages both the Stream worker groups and the Edge Nodes

Edge processing is limited as it is only one end node. (1 CPU core)
- Edge nodes can ingest a max of 200GB per day. 
- Stream worker groups can do more processing, and we can have more workers in the group to do more processing. A `passthru` [[Pipelines, Functions, Packs#Pipeline|Pipeline]] to Cribl TCP to Stream workers to handle larger volume.

**By default, Cribl Edge uses**
- Port 9420 for the Edge UI.
- Port 4200 for heartbeat metrics and configuration bundles. This is the port used for communication between Leader and Edge node. The API process is the entry point process on the leader node and it then forwards requests to the Connection Listener processes.
- Port 9000 (when using the installation script) for communication with the Leader Node and the Cribl UI.

> The connection listener process should increase by 1 every 10,000 nodes.

---
### Fleet Administration

**Fleets** are management groups used by Edge to organize nodes — analogous to Worker Groups in [[Stream]].
- **Sub fleets** can also be created.
- This is used to share configurations.
- Fleets should be logically organized, and some examples include organizing them based on OS type, data type, location, or others.

Fleets also support *inheritance*:
- sub level fleets of top level fleets collect the data they are required to, as well as the data of the top level fleet.
- sub level fleets support inheritance, that is, they also collect what the top level fleet collects.

*Fleet Mappings* allow us to specify which edge node connects to which fleet.
- Fleet mappings have priority over the edge node configuration.
- If no fleet is defined, the `default_fleet` is used.
- Only 1 Fleet Mapping ruleset can be active at one time, and it is recommended to copy the rules present in the default ruleset to the new ruleset and then adding changes.

Recommendations:
- When creating Fleets, 2-3 levels are enough because it can become confusing
- Separate critical systems
- Don't use the `default_fleet` and to disable all the sources in it.
- It is recommended to use the top level fleet name in the name of the sub fleets as well.
- Fleet names cannot have spaces, and they cannot be renamed.
- Fleets cannot be deleted if there are sub-fleets for it.


---
