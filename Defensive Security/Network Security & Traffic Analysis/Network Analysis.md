### General Notes

Traffic analysis is a process that involves determining the origin and impact of events. 
- The traffic is broken down into smaller chunks and is examined to check if it deviates from regular traffic, or if there is any malicious traffic from unauthorized remote connections.
- The traffic is also analyzed to check if there any trends that either match baseline normal behavior, or that of an adversary or attack, such as weird [[Port]]s or [[Protocol]]s being used.

Many tools like [[Firewall]]s, [[IDS & IPS]], and logging systems have signatures to detect attacks.
- These tools also provide visibility into the network, and are able to create a baseline of normal traffic to determine when any changes take place.
- These tools also send their logs to solutions like [[SIEM]]s, such as [[ELK - Elasticsearch, Kibana, & Logstash]] to monitor the traffic and correlate events.

Traffic capture can either be *passive* or *active*.
- **Passive** analysis is when a copy of the data is captured and has the operations performed on it, without directly interfering with the packets and the connections. *Port mirroring* is an example of such technique.
- **Active** analysis, also referred to as *in-line* analysis, is when real time analysis is conducted on the packets as they are moving. A *network tap*, or a *host with multiple Network Interface Cards* (NICs) is an example.

---
### Analysis in Practice

Traffic analysis is a dynamic process and it is influenced by what we are looking for. The process is comprised of several stages:
- **Descriptive Analysis**: The process of first describing the issue, then defining what we are looking for and when it happened, and then finally defining where we are looking (scope).
- **Diagnostic Analysis**: This provides insights through correlation and interpretation. It starts by first capturing traffic around the case of the issue, filtering out what is not needed, then inspecting and understanding the remaining captured data.
- **Predictive Analysis**: Predicts a model for the future by using analysis to identify trends and detect deviations. This includes evaluation of the current data and comparing it to both, the baseline, and to known markers of exploitation. Done by annotating everything and keeping summaries of relevant details. 
- **Prescriptive Analysis**: This is used to decide on what actions to take, or prescribe the solution.

However, the approach to analysis can be simplified by doing the following:
- Starting first with standard [[Protocol]]s and those that are relevant to the organization. Begin first with the internet related protocols, then move onto network communication protocols.
- Start looking for patterns.
- Start looking for any host to host communication.
- Look for unique events, such as weird user agents, weird requests, weird ports.

Below is a list of questions we can ask ourselves during the analysis process to keep on track.
- What type of traffic do you see? (protocol, port, etc.)
- Is there more than one conversation? (how many?)
- How many unique hosts?
- What is the timestamp of the first conversation in the PCAP (TCP traffic)
- What traffic can I filter out to clean up my view?
- Who are the servers in the PCAP? (answering on well-known ports, 53, 80, etc.)
- What records were requested or methods used? (GET, POST, DNS A records, etc.)

---
