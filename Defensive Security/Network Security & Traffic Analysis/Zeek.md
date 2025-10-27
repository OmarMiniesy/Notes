### General Notes

This is an open source network traffic analyzer.
- It produces log files that contain detailed records of connections made and all application layer activity. 
- Zeek has a scripting language that allows creating scripts that function similar to [[Suricata]] rules.

> The Zeek documentation can be found [here](https://docs.zeek.org/en/master/).

Zeek operates in the following modes:
- Fully passive traffic analysis, functioning as an [[IDS & IPS#Intrusion Detection Systems (IDS)|IDS]].
- `libpcap` interface for packet capture
- Real-time and offline (e.g., `PCAP`-based) analysis
- Cluster support for large-scale deployments

##### Architecture

The Zeek architecture is comprised of an **Event Engine** and the **Script Interpreter**.
- The *event engine* is used to reduce the packet stream into a series of high level *events* that describe the network activity.
- The *script interpreter* is then used to execute *event handlers* written in the scripting language to take actions based on the monitored activity.

---
### Using Zeek

To run Zeek on a captured `pcap`:
```bash
zeek -r <pcap_file.pcap>
```
- Zeek outputs the log files after it is run in the directory it is run.

> Zeek moves the logs every hour into a directory with name `YYYY-MM-DD` and compresses them using `gzip`. To handle compressed log files, use the tool `zcat` instead of `cat`.

---
### Zeek Logs

When Zeek performs analysis, it produces its output in the form of log files. There are several logs files, and these include:
- `conn.log`: This log provides details about each connection that Zeek detects.
- `dns.log`: Here, you'll find the details of [[Domain Name System (DNS)]] queries and responses.
- `http.log`: This log captures the details of [[HTTP]] requests and responses.
- `ftp.log`: Details of [[File Transfer Protocol (FTP)]] requests and responses are logged here.
- `smtp.log`: This log covers SMTP transactions, such as sender and recipient details.
- ...

> For a list of all the log files, check this [link](https://docs.zeek.org/en/master/logs/index.html).

---
### Dealing with Log Files

The structure of a log file starts first with a set of comments, then the actual data from the capture.
- Zeek outputs log files by default in *TSV* format, or Tab Separated Values.

Zeek can also output in *JSON*:
```bash
zeek -r <pcap-file.pcap> LogAscii::use_json=T
```

> To print out the *time* in *UTC* format, we can use the `-u` flag when using `cat` and `zeek-cut`.

###### For TSV Logs

As such, we can use the `awk` tool to capture the values we want from the columns we desire using [[Regular Expressions]]:
```
awk '/^[^#]/ {print $3, $10, $22}' dns.log
```
- We use `^[^#]` to ignore any line that begins with a `#`. The `^` matches beginning of line, and `^#` means to ignore the `#`. Therefore, it matches all lines that do not begin with `#`, ignoring the comments.
- Then, we specify the column we want by the number, as each number is based on the spaces. `AWK` splits fields by whitespace (spaces or tabs), so `$3` is the 3rd column, etc.

A better method is using `zeek-cut` which outputs only the values we need without the header lines:
```
cat dns.log | zeek-cut <column-name1> <column-name2> ...
```

###### For JSON Logs

We can use the `jq` tool to parse the JSON logs:
```bash
jq . dns.log
```
- This outputs the values in a clean format.
- To make it a compact print to print on the same line, we can use the `-c` flag.

To output specific values, we can then specify the names using dot notation:
```bash
jq -c '[."id.orig_h", ."query", ."answers"]' dns.log
```

> For more details, refer to the [[Dealing With Files of Different Types#JSON Files|Dealing with JSON Files]].

---
