### General Notes

A set of bash scripts and terminal commands used for analysis of [[Logs]] for [[Network Analysis]].

---

To get a count of the [[IP]] addresses in a log file separated by spaces and then removing the [[Port]]:
```
cut -d ' ' -f 5 firewall.log | cut -d ':' -f 1 | sort | uniq -c | sort -rn
```

