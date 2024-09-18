### Enumeration

To properly exploit a website created using [[WordPress]], enumeration must be performed.
- There are a variety of aspects that can be enumerated which can lead to promising information to be used while exploiting.

> Can also automate the process by using tools like `wfuzz` or `WPScan`.

###### 1. Core Version

The *software version number* of WordPress used can be helpful in searching for:
- Common misconfigurations.
- Default passwords for that version number.
- Known vulnerabilities for that version number.

To identify the software version:
- Look through the source code.
- Look for the `'<meta name="generator"` tag.
- Check for links to CSS or JS files that can provide hints about the version number.
- In the `readme.html` file.
###### 2. Plugins and Themes

Information about plugins and themes can be found by reviewing the source code using [[cURL]] and `grep` to hasten our search.

- Using passive enumeration:

``` bash
curl -s -X GET <URL> | sed 's/href=/\n/g' | sed 's/src=/\n/g' | grep 'wp-content/plugins/*' | cut -d"'" -f2
```

```bash
curl -s -X GET <URL> | sed 's/href=/\n/g' | sed 's/src=/\n/g' | grep 'themes' | cut -d"'" -f2
```

Not all plugins and themes can be passively discovered, sometimes, we need to try and access the files themselves of that software, using active enumeration.
- One technique is to use directory listing to show all the files in the directory.

```bash
curl -s -X GET http://blog.inlanefreight.com/wp-content/plugins/mail-masta/ | html2text
```

> Plugins can be active or inactive, and in both cases, they are still accessible. If a plugin is deleted, then it is inaccessible.

###### 3. Users

To identify users, we can start observing the posts and trying to discover the `userID` of these users.
- We can do that by sending a request to `/?author=<ID>`, and based on the response, we can identify whether that user exists or not, and the respective ID.

> The `admin` usually has `userID` of 1.

Another technique is to use the `JSON` endpoint that returns a list of users.
- This was the case in [[WordPress]] before version 4.7.1, after that, it was patched.

> We can try to send credentials to the `xmlrpc.php` file, and we can check if the credentials are valid based on the response. 


---
