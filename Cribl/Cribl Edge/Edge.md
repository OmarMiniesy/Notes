### General Notes

This is a data collection agent with centralized management, deployed directly on a node to collect data from it.
- Can collect [[Logs|logs]], metrics, application data, and more.
- Edge automatically discovers and collects this data without manual configuration.
- Can also perform data exploration close to the source to determine what needs to be collected — searching directly at the node reduces unnecessary data movement.
- Edge is vendor-agnostic: any data can be collected from any source.

Edge nodes can be grouped into logical fleets and sub-fleets, allowing them to share configurations.
- Edge nodes can be upgraded from the management platform without touching each node individually.

![[Edge.png]]

**Single Mode**: Run edge nodes on one machine without management by leader node.
**Distributed Mode**: The leader node manages the edge nodes.

**Fleets** are management groups used by Edge to organize nodes — analogous to Worker Groups in [[Stream]].
- **Sub fleets** can also be created.
- Fleets should be logically organized, and some examples include organizing them based on OS type, data type, location, or others.

The Leader node manages all the configurations for the worker nodes and the edge nodes.
- Communication with Edge nodes (fleets) takes place to inform edge nodes how to collect the data and the scheduled collection based on collector rules.
- Communication takes place through TCP [[Port]] 4200 for heartbeat metrics and notifications to edge nodes.
- [[HTTP]] on port 4200 is used to download configuration bundles.
- The leader node's resources should be scaled up to match the number of managed nodes and the volume of configuration activity.

> The *leader node* manages both the Stream worker groups and the Edge Nodes

Edge processing is limited as it is only one end node. (1 CPU)
- Stream worker groups can do more processing, and we can have more workers in the group to do more processing.

**By default, Cribl Edge uses**
- Port 9420 for the Edge UI.
- Port 4200 for heartbeat metrics and configuration bundles.
- Port 9000 (when using the installation script) for communication with the Leader Node

---
