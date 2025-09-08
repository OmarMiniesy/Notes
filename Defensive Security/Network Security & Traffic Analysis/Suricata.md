### General Notes

This is a tool used for network security monitoring and has many modes of operation.
- [[IDS & IPS|IDS]] mode: This is when Suricata acts as an observer by examining traffic and flagging potential attacks.
- [[IDS & IPS|IPS]] mode: This is when Suricata can be proactive. All traffic passes through Suricate checks and access is granted to the network only upon approval. This mode includes _rules_ that are used to detect and take action against malicious traffic.
- Intrusion Detection Prevention System mode: This combines both IDS and IPS, by examining network traffic and sending `RST` packets to terminate connections when needed.
- Network Security Monitoring mode: This is when Suricata becomes a logging tool that captures all network packets.

Suricate can operate on:
- Pre-captured `PCAP` files.
- Live input by reading data directly from a network interface. 

> The rules used by Suricate can be found at `/etc/suricata/rules/`, and variables used by the rule files can be found and edited at `/etc/suricata/suricata.yaml`.

---
### 
