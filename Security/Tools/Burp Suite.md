
### General Notes

> A tool that helps study and analyze web applications
> It is an **intercepting proxy**

> Can be used to detect [[Cross Site Scripting (XSS)]] vulnerabilities.
> Can be used to test [[SQL Injections]] vulnerabilities.
___

### Intercepting Proxy

 > A tool that can analyze and modify requests, as well as responses exchanged between [[HTTP]] client and server
 
* Intercept and modify requests and responses
* Build requests manually
* Crawl a website by visiting every page
* Fuzz web application by sending patterns of valid and invalid inputs to test behaviour

---

### History

> Burp collects information on HTTP traffic and stores it
1. Proxy > History
2. Target > Site Map

---

### Extensions

> Go the extensions tab and open the BApp store.
> Download the required extensions.

---

### View Response In Browser

> Need to open the burp proxy and enable it on the broswer to view responses in the browser and follow the trail of responses.

---

### Intruder

> To enumerate a single list multiple times, use the clusterbomb attack and set one of the payloads as null values.
> Set the number of null values to the number of repetittions wanted.

---

### Macro Sessions

> To add a macro, go to settings and then sessions.
> Add a rule and make sure its scope is set.
> Add a macro and select the requests needed in order and test the macro to make sure it works as required.

> This macro will work after every request in the desired tools in burp.

---
