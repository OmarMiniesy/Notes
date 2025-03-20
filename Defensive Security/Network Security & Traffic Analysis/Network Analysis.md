### General Notes

Traffic analysis is a process that involves determining the origin and impact of events. 
- The traffic is broken down into smaller chunks and is examined to check if it deviates from regular traffic, or if there is any malicious traffic from unauthorized remote connections.
- The traffic is also analyzed to check if there any trends that either match baseline normal behavior, or that of an adversary or attack, such as weird [[Port]]s or [[Protocol]]s being used.

Many tools like [[Firewall]]s, [[IDS & IPS]], and logging systems have signatures to detect attacks.
- These tools also provide visibility into the network, and are able to create a baseline of normal traffic to determine when any changes take place.
- These tools also send their logs to solutions like [[SIEM]]s, such as [[Elastic]] to monitor the traffic and correlate events.

Traffic capture can either be *passive* or *active*.
- **Passive** analysis is when a copy of the data is captured and has the operations performed on it, without directly interfering with the packets and the connections. *Port mirroring* is an example of such technique.
- **Active** analysis, also referred to as *in-line* analysis, is when real time analysis is conducted on the packets as they are moving. A *network tap*, or a *host with multiple Network Interface Cards* (NICs) is an example.

---


