
### General Notes

> Tool that connects to mysql instances on machines.
> Usually on [[Port]] 3306.

---

### Connect to Host

> To connect to host with a given [[IP]] address with given username. Try `root` as username to see if it works.
```
mysql -h <IP> -u <user/root>
```
> `-h` to specify host.

---

### Post Connection

> Can use normal SQL queries.

> To show the databases present.
``` SQL
SHOW databases;
```

> To use a given database.
```SQL
USE <database-name>;
```

> To show the tables inside the selected database.
``` SQL
SHOW tables;
```

---
