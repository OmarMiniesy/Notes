### General Notes

Exploiting servers that can accept many [[HTTP]] verbs and methods.
- Check the resulting [[HTTP]] response to see effect of exploitation.

>Can be done using [[netcat]]

---
### Exploiting HTTP Verbs
##### Enumerate available verbs

- Using `netcat`, connect and then send a request using the `options` verb.
```
nc example.site 80
OPTIONS / HTTP/1.1
```

> Similar to the usage of `netcat` in [[WebApplication Fingerprinting]].
##### Exploit `DELETE`

- Using `netcat`, connect and then send a request using the `delete` verb, with the path to the file specified.
```
nc example.site 80
DELETE /path/to/resource.php HTTP/1.1
```
##### Exploit `PUT`

Must know the size of the file to be uploaded. Use the `wc -m <filename>` to get size in bytes of the file.

- Using `netcat`, connect and then send a request using the `PUT` verb, with the path to the file specified.
```
nc example.site 80
PUT /payload.php HTTP/1.1
Content-type: text/html
Content-length: <size-in-bytes>

<?php shell-code ?>
```
##### Exploit `TRACE`

Used in [[Information Disclosure]].
- The web server responds with the exact request that was sent.
- Can be used to test for the hidden server side [[HTTP]] headers.

---
### Bypassing [[HTTP]] Basic Authentication

HTTP uses the basic authentication security measure to authenticate users.
- Taking username and password and encoding them using base64.

> To bypass this using verb tampering, we are basically bypassing the login functionality that requests a username and password that we do not have.

One technique is to try accessing the same page that requires login but by using a different [[HTTP]] method.
- For example, changing the request method from `GET` to `POST` in [[Burp Suite]].

Checking the available verbs that the web server accepts using an `OPTIONS` request through [[cURL]], which may reveal other verbs that are not handled properly by web server.

```bash
curl -i -X OPTIONS <url>
```

---
### Bypassing Filters

Sometimes due to insecure coding, some parameters or data is being accepted and handled by a certain [[HTTP]] method.
```PHP
$_POST['name']
```
- This `php` code takes the value of the `POST` parameter `name`.

> If we change the request method to `GET` for example and try supplying the value of the `name` parameter, the web server might not be configured to handle such case.

---
