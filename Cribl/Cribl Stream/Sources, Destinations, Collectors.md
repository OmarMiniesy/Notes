
### Sources

**Push Sources** are used to send data to Cribl Stream, and these are like agents.
**Pull Sources** are used to pull data from the source.
**Collector Sources** are used to fetch data intermittently, not continuously. Can be used to schedule data collection.
**System & Internal Sources** are used to provide internal metrics, system states, and Cribl internal data.

---
### Collector

Enable you to collect from local or remote data using: 
- on-demand data collection 
- schedule collection jobs 

The collector process follows:
- Leader node sends configuration needed to execute a collection job to a worker node.
- The worker node then discovers the data to be collected, the fetched data is then filtered, then the worker node will then forward the data to the appropriate route or pipeline and send it to its final destination.

---
### Destinations

**Streaming destinations** are those that accept data in real time or mini batches.
- [[SIEM]]s are an example of this.

**Non-Streaming destinations** are great for long term storage and accept data in batches or groups.
- [[Simple Storage Service (S3)]] buckets are an example of this.
- Cribl Stream uses a staging directory locally to format and write files in the correct format before sending them to the destination. The staging directory should be fast local storage since Cribl does active I/O there.
- Files in the staging directory are either **open** (actively being written to) or **closed** (finalized and ready to ship). Only closed files are moved to the destination.
- A file is closed and shipped when any of these conditions are met:
    - **Max file size** — file hits the size threshold
    - **Max file open time** — file has been open for too long, regardless of activity
    - **Max file idle time** — no new data has been written for too long
- If a new file needs to open but the limit of open files is reached, Cribl force-closes the oldest open file to make room, even if none of its conditions were met yet.

**Output Routers** are used to send data to multiple locations based on filters and rules.
- There are also special destinations such as `DevNull` to drop events, or `Default`, a default output to send data to.
- Rules are evaluated top-down with the first match being the winner.
- An output router cannot reference another to avoid cycles.
- Events that don't match rules are dropped.
- Data can be *cloned* to send it to multiple locations by setting the `Final` flag to `no`.

---
### Backpressure

Backpressure occurs when there are issues sending or receiving data on either the source or destination side.
- Specifically, it refers to the in-memory queue being overwhelmed with data.
- Persistent Queues (PQs) spill the overflow to disk to ensure no data is lost. Data is processed first-in, first-out once the pressure subsides.

Source-side backpressure leads to two options:
- Enable PQ only when pressure is detected from the destination.
- Keep PQ always on to act as a permanent buffer.

Destination-side backpressure can be handled in several ways. Not all destinations support all options:
- **Block**: Stop accepting new events; resume once the destination recovers.
- **Drop**: Discard events addressed to the destination.
- **Queue**: Spill events to a PQ until the destination is ready.

---
