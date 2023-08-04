
### General Notes

> The DOM, or Document Object Model is the browser's hierarchal representation of elements on page.
> Manipulated by JavaScript.

> DOM attacks arise when a website takes JavaScript from users, or a **source**, and passes it into a function, a **sink**.
> DOM vulnerabilities occcur when problems arise from client-side code manipulating attacker-controllable data.

> The URL is accessed via the `location` object.

---

### Taint-Flow 

> This is the flow between **sources** and **sinks**.
###### Source

> JavaScript property that accepts data from attacker.
> For example, the `location.search` takes the query parameters, which can be controlled.
> This also includes: 
* `document.referrer`.
* `document.cookie`.
* `document.URL`.
* `document.documentURI`.
* `document.URLUnencoded`.
* `document.baseURI`.
* `location`.
* `window.name`.
* `history.pushState`.
* `history.replaceState`.
* `localstorage`.
* `sessionStorage`.
* `Database`.
* Web messages.
* Stored Data.
* Reflected Data.
###### Sinks

> JavaScript function that can cause effects if attacker controlled data is passed to it.
> The `eval()` function is a sink because it processes its arguments as JavaScript. Javascript Injection.
> `document.body.innterHTML` is also a sink becuase it allows attackers to inject malicious HTML and execute Javascript.
> More sinks:
* `document.write`. Used in [[Cross Site Scripting (XSS)#DOM-Based XSS]].
* `window.location`. Used in [[DOM Based Vulnerabilities#Open Redirection]].
* `document.cookie`. Used in [[DOM Based Vulnerabilities#Cookie Manipulation]].
* `document.domain`. Used in Document-domain manipulation.
* `WebSocket()`. Used in [[WebSockets]]-URL poisoning.
* `element.src`. Used in Link Manipulation.
* `postMessage()`. Used in Web Message Manipulation.
* `setRequestHeader()`. Used in Ajax request-header manipulation.
* `FileReader.readAsText()`. Used in local file-path manipulation.
* `ExecuteSQL()`. Used in client side [[SQL Injections]].
* `sessionStorage.setItem()`. Used in HTML5-storage manipulation.
* `document.evaluate()`. Used in Client-side XPath injection.
* `JSON.parse()`. Used in Client-side JSON injection.
* `element.setAttribute()`. Used in DOM-data manipulation.
* `RegExp()`. Used in Denial of Service attacks.

---

### Open Redirection

> An open redirect vulnerability occurs when an application allows a user to control a redirect or forward to another URL. If the app does not validate untrusted user input, an attacker could supply a URL that redirects an unsuspecting victim from a legitimate domain to an attacker’s phishing site.

> Open redirection vulnerabilities arise when a script writes attacker controllable data into a sink that can trigger cross-domain navigation.
> What we try to do is to change the URL of the browser, and we can do that if we can abuse misconfigured scripts.
> Some of the sinks that can lead to open redirection:

```
location 
location.host 
location.hostname 
location.href 
location.pathname 
location.search 
location.protocol 
location.assign() 
location.replace() 
open() 
element.srcdoc 
XMLHttpRequest.open() 
XMLHttpRequest.send() 
jQuery.ajax() 
$.ajax()
```

> If an attacker can modify the string passed to a redirection API, then this vulnerability can be escalated into a JavaScript injection attack.
> Basically, we can use `javascript:` and enter javascript code that can be executed into the URL.
> Once the URL is pressed, the javascript code is executed.

###### Prevention

> To prevent Open Redirection, avoid dynamically setting redirection targets using data from untrusted source.

---

### Cookie Manipulation

