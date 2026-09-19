### Sources

These are configurations that enable [[Stream]] to collect and receive data from various locations.
- **Push Sources** are used to send data to Cribl Stream, and these are like agents. Data pushed to stream is load balanced onto the worker nodes.
- **Pull Sources** are used to pull data from the source. This runs on a scheduled fetch to regularly pull updated data.
- **Collector Sources** are used to fetch data intermittently, not continuously. Can be used to schedule data collection.
- **System & Internal Sources** are used to provide internal metrics, system states, and Cribl internal data.

Cribl sources all use one of the 3 protocols. Some sources can utilize more than 1.
- [[HTTP]]/[[HTTPS]]: These forward the data to an HTTP endpoint and integrates with a lot of APIs. Full control of HTTP headers and HTTP methods and authentication methods and payload formatting.
- [[Transport Layer#TCP|TCP]]: Transmits data reliably and in order to a specific host and port. Allows encryption and load balancing.
- [[Transport Layer#UDP|UDP]]: Transmits data to a host and port in a fast manner, not reliable. Used for low overhead and minimal latency.

All sources can be managed through a single pane of glass, and an API is available to automate stuff.
- Git is also included here and can be used to store the configurations for these sources.
- Sources also support role based access control.

**Live Capture** is also allowed while working to check the shape of the data to assist configuration of pipelines and any data modifications.
- This live capture can be saved to a file and reused.

##### Pull Sources
The *poll interval* variable should be set which defaults to 15 minutes. This is the time period between pull requests.
- 60 should be divisible by the chosen number.

> Pull sources work through a discovery and collection phase. Data is paginated as well.

##### Collector
Enable you to collect from local or remote data using: 
- on-demand data collection 
- schedule collection jobs 
- It is known for ingesting data intermittently rather than continuously.

The collector process is as follows:
- Leader node sends configuration needed to execute a collection job to a worker node.
	- This can be sent to multiple worker nodes to parallelize the task.
- The worker node then discovers the data to be collected.
- The fetched data is then filtered using a match filter
- The worker node will then forward the data to the appropriate route or pipeline and send it to its final destination.

> The leader node chooses the worker node to orchestrate this job to. It does this by choosing the least busy worker node. This is called *least in flight* scheduling. If the leader node is down, this process does not happen

---
### Setting up Windows Event Collector

This is a source that sends [[Windows Events Log]].
- Usually in a normal environment, a **Windows Event Collector** server is required.
- The hosts send their logs to that server after performing certain [[Group Policy Object]]s.
- This is done using a **Windows Event Forwarder** setup on the clients that send these logs.

However, we can replace the use of this windows event collector server, and set [[Stream]] to be the destination of sending the logs. To do this, the following requirements should be done:
- Setup an authentication method with Stream, using either mutual [[Transport Layer Security (TLS)]] or [[Kerberos]].
- Ensure that [[Domain Name System (DNS)]] resolution is set and the Stream collector is resolvable by the sending clients.
- Setup time synchronization between the clients and Cribl stream for Kerberos to work.
- Configure group policies to choose the correct Stream Subscription, server, and necessary permissions.

We also need to setup a Windows Event Forwarder source that will be configured to read and ingest this data.
- Authentication, ports, subscriptions, and the match queries. 

For the Subscription:
- Choose a unique name.
- Choose the format of the data. 
	- `Raw` data is [[XML]]
	- `RenderedText` includes additional information
- The Read Existing and Use bookmarks are used to send historical logs again or only send the new events.
- Compression is used to enable receiving compressed events.

For the Query Builder:
- Build using simple mode or raw XML to write XPath queries.
- Choose the event IDs to collect. (Max of 22 event IDs per filter)
- Can also add fields to all collected events.

![[Sources, win-1.png]]

For the actual windows clients to send information to Stream:
- Ensure Windows Remote Management is running by running `winrm quickconfig`.
- Ensure Event Log Read Permissions are set.
- Configure the Group Policy
- Configure the Target Subscription Manager
- Deploy the Group Policy

---




