### General Notes

This is an open source and *rule-based* [[IDS & IPS|NIDS/NIPS]].
- Malicious network activity is defined through a set of rules which generate alerts when packets that match this description are matched.
- The official website to download and for the documentation: [Snort](https://www.snort.org/documents#OfficialDocumentation).

> Snort in *passive* mode only observes and detects, but in *inline* mode it can take action like blocking traffic.

Snort has several use cases:
1. *Packet sniffer*: Similar to tools like `tcmpdump` and is used in **sniffer mode**.
2. *Packet logger*: Useful for network traffic debugging and is used in **packet logger mode**.
3. **Network Intrusion Prevention System (NIPS)** & **Network Intrusion Detection System (NIDS) mode**.
4. *PCAP Investigations*: Used to read and investigate `.pcap` files.

Snort uses *configuration files* that specifies rules, plugins, detection mechanisms, actions, and output settings, and more settings.
- There can be multiple configuration files present for different use cases, but only 1 configuration file can be active during runtime.

> The `snort.lua` file is the main configuration file, and the `local.rules` is the user generated rules file. They are found in the `/etc/snort` directory.

###### Preprocessors
Snort has plugins called *preprocessors* which are tailored for specific [[Protocol]]s and traffic types.
- Preprocessors are only called a single time per packet and may perform highly
complex functions
###### Detection Plugins
Snort also has *detection* plugins which are used to check a single aspect of a packet for a value defined within a rule and determine if the packet data meets their acceptance criteria.

---
### Snort Rules

> The official Snort documentation for for writing rules: [Rule Writing Guide](https://docs.snort.org/).

To run Rules with snort:
```
snort --rule-path </directory-with-rule-files>
```

Each rule has a rule header and rule options.
- To use the rules that are to be added, must specify the file path that contains these rules with the `-c` flag.
- The rule header includes the following fields that can be used with binary operations and filters:
	- Action: alert, log, drop (block and log), reject (block, log, and terminate session).
	- [[Protocol]]
	- Source [[IP]]
	- Source [[Port]]
	- Direction: `->` which indicates source to destination, or `<>` which indicates bi-directional flow.
	- Destination [[IP]]
	- Destination [[port]]
- The rule options are placed inside brackets and separated by `;` semicolons in the form of `key:value` pairs.
	- The types of usable options are *general rule options*, *payload rule options*, and *non-payload rule options*.
	- These can all be used together in different combinations.

> All rules created by the user are local rules and are found in the `/etc/snort/rules/local.rules` file.

*General Rule Options*. These are the options that are included with all rules. These are the data fields that can be used:
- `Msg`: Once the rule is triggered, this message will appear in the console or the log.
- `Sid`: The Snort Rule ID. There are predefined scopes for the SIDs, and each SID must be unique.
- `Reference`: This adds information to explain the purpose of the rule, like a CVE.
- `Rev`: This indicates how many time the rule was revised or improved.

> `Sid < 100` is for reserved rules, `100 < Sid < 999,999` is for rules coming with the build, and `Sid >= 1,000,000` are rules created by the user.

*Payload Detection Rule Options*. These are used to match for exact payload content in the packet. These are the data fields that can be used:
- `Content`: The data to match against in the payload of the packet. It matches by ASCII, hex, or both. **This is case sensitive.**
- `Nocase` is an option used to specify that it should not be case sensitive.
- `Fast_pattern` is an option to speed up the search operation by prioritizing content search.

*Non-Payload Detection Rule Options*. These are used to match for content in non-payload data of the packets.
- `ID`: used on the ID of the [[IP]].
- `Flags`: Used to match for the [[Transport Layer#TCP]] flags, FIN, SYN, RST, PSH, ACK, URG.
	- `F`, `S` ,`R`, `P`, `A`, `U`.
- `Dsize`: To filter for packet payload size.
	- `min<>max`
	- `>min`
	- `<max`
- `Sameip`: Checks if the source and destination IP are the same.

---
### Using Snort

> The command line basics for Snort can be found [here](https://docs.snort.org/start/help).

To verify that snort is installed, we can check the version using the `-V` flag.
```
snort -V
```

To identify the configuration file to be used, use the `-c` flag.
```
sudo snort -c </path/to/file>
```
- Usually, there is one here `/etc/snort/snort.lua`.

To test that the configuration is correct, use the `-T` flag.
```
sudo snort -c </path/to/file> -T
```

Listing all available Snort modules:
```
snort --list-modules
```

Getting help on a specific Snort module:
```
snort --help-module <module>
```

Getting help on a specific rule option module:
```
snort --help-module <module>
```


##### Sniffer Mode

This mode captures and logs network traffic similar to a packet sniffer like [[Wireshark]] to the console. There are flags that can be used to show different types of data for the packets:
- `-v` for verbosity, it shows the TCP/[[IP]] output.
- `-d` for data, shows the packet payload.
- `-e` shows the [[Transport Layer]] headers.
- `-X` shows full packet details in *hex*.
- `-i <eth0>` for interface, allows specifying a specific interface to sniff on.

##### Logger Mode

This mode is used to log packets when the correct parameters are used alongside the normal sniffer mode.
- `-l <directory>` for logger mode and where to dump the logs. It dumps in the default output folder of `/var/log/snort` in `tcpdump` format. The default directory can be changed in the `snort.config` file.
- `-K ASCII` is used to log packets in ASCII format. ASCII format provides multiple files in human readable format that can be opened using a text editor.
- `-r <filename>` for reading a passed packet dump file `.pcap`, it shows information about the file and packets inside. Can use filters to search for and query the data of the packets using Berkeley Packet Filters. Check out [[#PCAP Investigation Mode]].
- `-n` for the number of packets to read, after that the process is terminated.

> Files output using snort using `sudo` will have `sudo` privileges and require `sudo` privileges to be read. We can change the owner of the directory using `sudo chown <user> -R <directory>`.

##### IDS/IPS Mode

This mode is used to manage traffic according to rules using these flags:
- `-c <filename> -T` to specify the configuration file or the file with the rules. The `-T` is only used to test the file and is not used during normal operation.
- `-N` to disable logging mode.
- `-D` to run Snort in background mode as a background process.
- `-A <mode>` for the alert mode. Using the rules found in the configuration file, if an alert is triggered, an alert file is created. Can be used with the `-l` flag to specify the log file to output the data to.
	- `console`: Provides fast style alerts on the console screen.
	- `cmg`: Provides basic header details with payload in hex and text format.
	- `full`: Full alert mode, providing all possible information about the alert. This outputs to a file, not the console.
	- `fast`: Fast mode, shows the alert message, timestamp, source and destination [[IP]] along with [[Port]] numbers. This outputs to a file, not the console.
	- `none`: Disabling alerting, only the log file is produced.

To run Snort as an **IPS**, we need to specify the following:
- `-Q` for IPS inline mode.
- `--daq <module>`: The Data AcQuisition module, which can be `afpacket` to allow Snort to process packets directly. There are 6 DAQ modules available, which are:
	- *`pcap` default sniffer mode.*
	- *`afpacket` inline IPS mode.*
	- `ipq` inline Linux using Netfilter.
	- `nfq` inline mode Linux.
	- `ipfw` inline on OpenBSD and FreeBSD.
	- `dump` which is testing mode of inline.
- `-i <int1>:<int2>` At least two interfaces that the IPS will be active between.

```bash
sudo snort -c /etc/snort/snort.conf -Q --daq afpacket -i eth0:eth1 -A console
```
- We specify `-A console` for the console mode to show alerts on the console in a quick manner.

##### PCAP Investigation Mode

This mode is used to give statistics and create alerts based on the traffic in the `.pcap` file by utilizing configuration files and the rules. It uses these flags:
- `-r <pcap file>`: To investigate a single `.pcap` file.
- `--pcap-list="<space separated list of pcaps>"`: To investigate several `.pcap` files.
- `--pcap-show`: To show the `.pcap` file name on the console.

For example:
```bash
sudo snort -c /etc/snort/snort.conf --pcap-list="icmp-test.pcap http2.pcap" -A console --pcap-show
```

---
