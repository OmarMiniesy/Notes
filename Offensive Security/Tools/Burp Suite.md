
### General Notes

A tool that helps study and analyze web applications
- It is an **intercepting proxy**

- Can be used to detect [[Cross Site Scripting (XSS)]] vulnerabilities. 
- Can be used to test [[SQL Injections]] vulnerabilities.

___
### Intercepting Proxy

 > A tool that can analyze and modify requests, as well as responses exchanged between [[HTTP]] client and server
 
* Intercept and modify requests and responses
* Build requests manually
* Crawl a website by visiting every page
* Fuzz web application by sending patterns of valid and invalid inputs to test behavior

##### To Intercept For Other Tools

Using `proxychains`, we can use proxies for tools like [[cURL]]. 
- Can inspect requests and responses more accurately.

1. Open `/etc/proxychains4.conf`.
2. Add to the proxy sections at the very end of the file `http 127.0.0.1:8080`. This sets BurpSuite as our proxy.
3. Optional: set quiet mode by uncommenting `quiet mode` in the file.

To use `proxychains`, simply prepend it while using another tool as another argument:

```bash
proxychains curl www.google.com
```

---

### History

Burp collects information on HTTP traffic and stores it
1. Proxy > History
2. Target > Site Map

---

### Extensions

Go the extensions tab and open the BApp store.
- Download the required extensions.

---

### View Response In Browser

Need to open the burp proxy and enable it on the browser to view responses in the browser and follow the trail of responses.

---

### Intruder

To enumerate a single list multiple times, use the `clusterbomb` attack and set one of the payloads as null values.
- Set the number of null values to the number of repetitions wanted.

---

### Macro Sessions

To add a macro, go to settings and then sessions.
- Add a rule and make sure its scope is set.
- Add a macro and select the requests needed in order and test the macro to make sure it works as required.

> This macro will work after every request in the desired tools in burp.

---
