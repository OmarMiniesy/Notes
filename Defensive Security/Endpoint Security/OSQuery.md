### General Notes

Open source agent that converts the operating system into a relational database that can be queried using *SQL*.
- Used for [[Threat Hunting]], [[Incident Handling]], ...
- Works on Windows, Linux, and FreeBSD.

> To use interactively, run the `osqueryi` command in the shell.

Since running `OSQuery` on single endpoint only queries the data on this machine, using `Kolide Fleet` allows querying multiple endpoints.

> The OSQuery [documentation](https://osquery.readthedocs.io/en/stable/).

---
### Using OSQuery

To get help and show a list of available commands:
```powershell
.help
```

To list the tables present to be queried:
```powershell
.tables
.tables <abc>
```
- To list all the tables with the term `abc` in them, add it after the `.tables`. This is used to check which tables have a certain name.

To understand the column names and data types of the columns of the table, or the *table schema*, use this command:
```powershell
.schema <table_name>
```
- The entire schema documentation is found here [link](https://osquery.io/schema/5.5.1/).

##### Writing Queries

Using normal SQL syntax, queries can be created using:
- `SELECT`
- `FROM`
- `WHERE`, can use `=`. `<>` (not equal), `>, >=`, `<, <=`, `BETWEEN`, `LIKE`, `%` (multiple character wild card), `_`(single character wild card).
- `LIMIT`
- `JOIN`
- Other functions and keywords are allowed with some exceptions.

When using wildcards with folder structures, there rules apply:
- `%` : Match all files and folders for one level.
- `%%` : Match all files and folders recursively.
- `%abc` : Match all within-level ending in `abc`.
- `abc%` : Match all within-level starting with `abc`.

Some tables *require* a `WHERE` clause in the query for it to work properly.
- `file` table.

---
