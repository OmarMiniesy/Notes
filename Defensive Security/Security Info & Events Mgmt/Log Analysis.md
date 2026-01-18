### General Notes

Log analysis can be done via [[SIEM]]s like [[Splunk]] or [[ELK - Elasticsearch, Kibana, & Logstash]]. For immediate analysis during [[Incident Handling]] & response, tools can be used like:
- `cat`
- `grep`
- `sed`
- `sort`
- `uniq`
- `awk`
- `sha256sum`
- [[Eric Zimmerman Tools]]
- `Get-FileHash`

[LogViewer](https://github.com/sevdokimov/log-viewer) is a Web application for monitoring server logs in real-time in the browser.
- Allows for filtering and searching.

> Additionally, proper acquisition should be observed by taking the log file's **hash during collection** to ensure its admissibility in a court of law.

---
### Techniques

To create a parsed and consolidated log file, you can use a combination of Unix tools like `cat`, `grep`, `sed`, `sort`, `uniq`, and `awk`. Here's a step-by-step guide:
1. Use `awk` and `sed` to normalize the log entries to the desired format. For this example, we will sort by date and time:
```yaml
# Process nginx access log
awk -F'[][]' '{print "[" $2 "]", "--- /var/log/gitlab/nginx/access.log ---", "\"" $0 "\""}' /var/log/gitlab/nginx/access.log  | sed "s/ +0000//g" > /tmp/parsed_consolidated.log

# Process rsyslog_cron.log
awk '{ original_line = $0; gsub(/ /, "/", $1); printf "[%s/%s/2023:%s] --- /var/log/websrv-02/rsyslog_cron.log --- \"%s\"\n", $2, $1, $3, original_line }' /var/log/websrv-02/rsyslog_cron.log >> /tmp/parsed_consolidated.log

# Process rsyslog_sshd.log
awk '{ original_line = $0; gsub(/ /, "/", $1); printf "[%s/%s/2023:%s] --- /var/log/websrv-02/rsyslog_sshd.log --- \"%s\"\n", $2, $1, $3, original_line }' /var/log/websrv-02/rsyslog_sshd.log >> /tmp/parsed_consolidated.log

# Process gitlab-rails/api_json.log
awk -F'"' '{timestamp = $4; converted = strftime("[%d/%b/%Y:%H:%M:%S]", mktime(substr(timestamp, 1, 4) " " substr(timestamp, 6, 2) " " substr(timestamp, 9, 2) " " substr(timestamp, 12, 2) " " substr(timestamp, 15, 2) " " substr(timestamp, 18, 2) " 0 0")); print converted, "--- /var/log/gitlab/gitlab-rails/api_json.log ---", "\""$0"\""}' /var/log/gitlab/gitlab-rails/api_json.log >> /tmp/parsed_consolidated.log
```

2. **Optional:** Use `grep` to filter specific entries:
```yaml
grep "34.253.159.159" /tmp/parsed_consolidated.log > /tmp/filtered_consolidated.log
```

3. Use `sort` to sort all the log entries by date and time:
```yaml
sort /tmp/parsed_consolidated.log > /tmp/sort_parsed_consolidated.log
```

4. Use `uniq` to remove duplicate entries:
```yaml
uniq /tmp/sort_parsed_consolidated.log > /tmp/uniq_sort_parsed_consolidated.log
```

---
