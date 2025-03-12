### General Notes

This is an open source and *rule-based* [[IDS & IPS|NIDS/NIPS]].
- Malicious network activity is defined through a set of rules which generate alerts when packets that match this description are matched.
- The official website to download and for the documentation: [Snort](https://www.snort.org/).

Snort has 3 use cases:
1. *Packet sniffer*: Similar to tools like `tcmpdump` and is used in **sniffer mode**.
2. *Packet logger*: Useful for network traffic debugging and is used in **packet logger mode**.
3. **Network Intrusion Prevention System (NIPS)** & **Network Intrusion Detection System (NIDS) mode** 

Snort uses *configuration files* that specifies rules, plugins, detection mechanisms, actions, and output settings, and more settings.
- There can be multiple configuration files present for different use cases, but only 1 configuration file can be active during runtime.

---
### Using Snort

To verify that snort is installed, we can check the version using the `-V` flag.
```
snort -V
```

To identify the configuration file to be used, use the `-c` flag.
```
sudo snort -c </path/to/file>
```
- Usually, there is one here `/etc/snort/snort.conf`.

To test that the configuration is correct, use the `-T` flag.
```
sudo snort -c </path/to/file> -T
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
- `-r <filename>` for reading a passed packet dump file `.pcap`, it shows information about the file and packets inside. Can use filters to search for and query the data of the packets using Berkeley Packet Filters.
- `-n` for the number of packets to read, after that the process is terminated.

> Files output using snort using `sudo` will have `sudo` privileges and require `sudo` privileges to be read. We can change the owner of the directory using `sudo chown <user> -R <directory>`.

##### IDS/IPS Mode

