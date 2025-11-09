### Overview

Me using Snort overtime and the commands I found useful.

- When doing a search using *Hex*, place the Hex data in between two pipes, `|`, like so: `| 89 50 4E 47 0D 0A 1A 0A|`.
- To look for certain file types, try using their signatures as based on this list of signatures [here](https://en.wikipedia.org/wiki/List_of_file_signatures).

---
### Rules & Commands

A rule that detects any *TCP* packets flowing to and from [[Port]] 80, then logs into a file all alerts generated:
```bash
-- local.rules --
alert tcp any 80 -> any any (msg:"Attack attempt!"; sid:1000001;)
alert tcp any any -> any 80 (msg:"Attack attempt!"; sid:1000002;)

-- terminal --
sudo snort -r file.pcap -c local.rules -A full -l .
```
- Here, we specify the `pcap` file with `-r`, the custom rules file with `-c`.
- We also specify that all alerts be logged in full and to the log file in the current directory.

---
### Log Files

We can view the log files using [[Snort]], and we can also use dedicated tools like [[Wireshark]] or [[Tcpdump]] as the output log files are **binary log file**s in **pcap format**.
- Using the `-r` flag for Snort and Tcpdump to pass the path of the log file.

To view all plain text in the snort log file, we can use `Strings`.
- This shows all plain text, like hostnames, services, and string values.

---
