### General Notes

There are various types of [[Stream]] destinations:
- Streaming Destinations
- Non-Stream Destinations
- Others

> The same data source can send data to multiple destinations with different formats as expected by those destinations.

Cribl destinations use either [[HTTP]], TCP, or UDP. ([[Transport Layer]]).
- This is similar to [[Sources]].
- HTTP destinations also offer **retry** options, which sends the data again if it failed to send. There are several settings for this:
	- `Retry-after` - [[HTTP]] header that specifies a delay of when to send again. This takes precedence over other retry settings.
	- `pre-backoff interval` - initial delay before the first retry
	- `backoff multiplier` - multiplier for exponential backoff after retries
	- `backoff limit` - maximum delay between any 2 retries

![[Destinations, 2.png]]

#### Streaming Destinations
**Streaming destinations** are those that accept data in real time or mini batches.
- [[SIEM]]s are an example of this.

#### Non-Streaming Destinations
**Non-Streaming destinations** are great for long term storage and accept data in batches or groups.
- [[Simple Storage Service (S3)]] buckets are an example of this.
- Cribl Stream uses a staging directory locally to format and write files in the correct format before sending them to the destination. The staging directory should be fast local storage since Cribl does active I/O there.
- Files in the staging directory are either **open** (actively being written to) or **closed** (finalized and ready to ship). Only closed files are moved to the destination.
- A file is closed and shipped when any of these conditions are met:
    - **Max file size** — file hits the size threshold
    - **Max file open time** — file has been open for too long, regardless of activity
    - **Max file idle time** — no new data has been written for too long
- If a new file needs to open but the limit of open files is reached, Cribl force-closes the oldest open file to make room, even if none of its conditions were met yet.

##### Others
**Output Routers** are used to send data to multiple locations based on filters and rules.
- Rules are evaluated top-down with the first match being the winner.
- An output router cannot reference another to avoid cycles.
- Events that don't match rules are dropped.
- Data can be *cloned* to send it to multiple locations by setting the `Final` flag to `no`.
- Output routers cannot reference other output routers to avoid circular loops.

> There are also special destinations such as `DevNull` to drop events, or `Default`, a default output to send data to.

---
### Troubleshooting

![[Destinations, 1.png]]

Can also configure notifications to be generated when a destination faces an issue based on conditions including:
- [[Architecture#Backpressure|Backpressure]] is activated
- Persistent queue is used
- Unhealthy destination

---