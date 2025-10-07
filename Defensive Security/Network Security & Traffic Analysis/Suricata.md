### General Notes

This is a tool used for network security monitoring and has many modes of operation.
- *[[IDS & IPS|IDS]] mode*: This is when Suricata acts as an observer by examining traffic and flagging potential attacks.
- *[[IDS & IPS|IPS]] mode*: This is when Suricata can be proactive. All traffic passes through Suricate checks and access is granted to the network only upon approval. This mode includes _rules_ that are used to detect and take action against malicious traffic.
- *Intrusion Detection Prevention System mode*: This combines both IDS and IPS, by examining network traffic and sending `RST` packets to terminate connections when needed.
- *Network Security Monitoring mode*: This is when Suricata becomes a logging tool that captures all network packets.

> Suricata [documentation](https://docs.suricata.io/).

Suricate can operate on:
- Pre-captured `PCAP` files.
- Live input by reading data directly from a network interface. 

Suricata can then output logs, alerts, network flows.
- Also outputs the `EVE` which is a JSON format that records alerts, [[HTTP]], [[Domain Name System (DNS)]], [[Transport Layer Security (TLS)]] metadata, flow, NetFlow, and more.
- Also outputs `Unified2` output which is [[Snort]] binary alert format and can be read using `us2pewfoo` Snort tool.

> The rules used by Suricate can be found at `/etc/suricata/rules/`, and variables used by the rule files can be found and edited at `/etc/suricata/suricata.yaml`. Custom rule file paths can be added in the `suricata.yaml` file.

> Output from Suricata can be found in the `/var/log/suricata` directory. 

##### Network Flows

A flow in Suricata terms is a set of packets passing through a single network interface in a specific direction and between a pair of source and destination endpoints.
- Suricata assigns `flow_id`s for improved tracking and correlation.

---
### Using Suricata

To ensure that the configuration file is correct, we can run this command:
```bash
sudo suricata -T -c /etc/suricata/suricata.yaml
```

To read `PCAP` files:
```bash
suricata -r <file-path.pcap> -k none -l .
```
- OPTIONAL: To bypass checksums, use the `-k`.
- OPTIONAL: To log in a specified directory, use `-l`.

To use live input, we need to first obtain an interface to listen on then specify it:
```bash
sudo suricata --pcap==<INTERFACE> -vv
```

To operate as an IPS, or in inline mode:
```bash
sudo iptables -I FORWARD -j NFQUEUE
sudo suricata -q 0
```
- First command sends packets to the queue and then we run `suricata` on the queue.
- Suricata here inspects each packet, applies rules, and decides whether to accept, drop, or modify packets.

To operate as an IDS:
```bash
sudo suricata -i <INTERFACE>
OR
sudo suricata --af-packet=<INTERFACE>
```

#### Extracting Files

To be used for [[DFIR]] and analysis, we can extract files transferred over a large number of [[Protocol]]s.
- This can be configured in the `suricata.yaml` file by making these changes in the `file-store` section:
```yaml
file-store:
   version: 2
   enabled: yes
   force-filestore: yes
```
- We also need to add a rule in the `local.rules` file. The output files can be viewed using `xxd`.
```
alert http any any -> any any (msg:"FILE store all"; filestore; sid:2; rev:1;)
```

#### Rule Reloading & Updates

To update the rules while Suricata is running without interruption, the following changes to the `suricata.yaml` file can be done in the `detect-engine` section:
```yaml
detect-engine:
   - reload: true
```
- Then, refreshing the rule set by using the `kill` command:
```bash
sudo kill -usr2 $(pidof suricata)
```

To update the Suricata rule set, we can use the `suricata-updata` tool:
```bash
sudo suricata-update
```

To list a set of available rule sources:
```bash
sudo suricata-update list-sources
```

To enable a particular rule source:
```bash
sudo suricata-update enable-source <Source-name>
```

> Ensure restarting the Suricata service after doing any changes using `sudo suricata-update` and `sudo systemctl restart suricata`.


---
### Suricata Outputs

Suricata records data into logs in the `/var/logs/suricata` directory that needs root level access to access and manipulate.
- This includes also the `eve.json`, `fast.log`,  and `stats.log` files.

> An option exists to activate particular outputs instead of the default `eve.log` file.
##### `eve.json`

The `eve.json` file contains JSON objects containing information such as: `timestamps`, `flow_id`, and `event_type`.
- Exists at `/var/log/suricata/old_eve.json`.
- Can be used with `jq` command line tool to filter using JSON. Check out [[Dealing With Files of Different Types#JSON Files|JSON File Manipulation]].

To filter for *alert events* or *DNS events* only:
```bash
cat /var/log/suricata/old_eve.json | jq -c 'select(.event_type == "alert")'
cat /var/log/suricata/old_eve.json | jq -c 'select(.event_type == "dns")'
```

##### `fast.log`

The `fast.log` file is a test based log file that records alerts only.
- Exists at `/var/log/suricata/old_fast.log`

---
