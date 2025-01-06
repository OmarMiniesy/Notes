
### General Notes

Tool that connects to `mysql` instances on machines.
- Usually on [[Port]] 3306.

---
### Commands

* To connect to host.
```
mysql -h <IP> -u <user> -p'password'
```
> `-h` to specify host.
> `-u` to specify user.
> `-p` to enter password. If there is no password, don't add `-p`. Can either add the password like that, or don't add it to the command but enter it when prompted.
> `-P` to specify port. (optional).

* To show the databases present.
``` SQL
SHOW databases;
```

*  To use a given database.
```SQL
USE <database-name>;
```

* To return the current database.
```SQL
SELECT database();
```

*  To show the tables inside the selected database.
``` SQL
SHOW tables;
```

* To see the columns and data types of a table.
```SQL
DESCRIBE <table-name>;
```

---