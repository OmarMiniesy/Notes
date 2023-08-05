
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
> The `eval()` function is a sink because it processes its arguments as JavaScript. [[DOM Based Vulnerabilities#JavaScript Injection]] .
> `document.body.innterHTML` is also a sink becuase it allows attackers to inject malicious HTML and execute Javascript.
> More sinks:
* `document.write`. Used in [[Cross Site Scripting (XSS)#DOM-Based XSS]].
* `window.location`. Used in [[DOM Based Vulnerabilities#Open Redirection]].
* `document.cookie`. Used in [[DOM Based Vulnerabilities#Cookies Manipulation]].
* `document.domain`. Used in [[DOM Based Vulnerabilities#Document Domain Manipulation]].
* `WebSocket()`. Used in [[DOM Based Vulnerabilities#WebSockets -URL poisoning]].
* `element.src`. Used in [[DOM Based Vulnerabilities#Link Manipulation]].
* `postMessage()`. Used in [[DOM Based Vulnerabilities#Web Message Manipulation]].
* `setRequestHeader()`. Used in [[DOM Based Vulnerabilities#Ajax Request-Header Manipulation]].
* `FileReader.readAsText()`. Used in [[DOM Based Vulnerabilities#Local File-Path Manipulation]].
* `ExecuteSQL()`. Used in [[DOM Based Vulnerabilities#Client-Side SQL Injections]].
* `sessionStorage.setItem()`. Used in [[DOM Based Vulnerabilities#HTML5-Storage Manipulation]].
* `document.evaluate()`. Used in [[DOM Based Vulnerabilities#Client-Side XPath Injection]].
* `JSON.parse()`. Used in [[DOM Based Vulnerabilities#Client-Side JSON Injection]].
* `element.setAttribute()`. Used in [[DOM Based Vulnerabilities#Data Manipulation]].
* `RegExp()`. Used in [[DOM Based Vulnerabilities#Denial of Service]].

> All the attacks work by creating a URL that if visited by another user, will cause the user's browser to open something vulnerable depening on the attack.
> What we try to do is to change the URL of the browser, and we can do that if we can abuse misconfigured scripts.

---
### Open Redirection

> An open redirect vulnerability occurs when an application allows a user to control a redirect or forward to another URL. If the app does not validate untrusted user input, an attacker could supply a URL that redirects an unsuspecting victim from a legitimate domain to an attacker’s phishing site.

> Open redirection vulnerabilities arise when a script writes attacker controllable data into a sink that can trigger cross-domain navigation.
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

### [[Cookies]] Manipulation

> Cookie maipulation vulnerabilities arise when a script can write attacker controllable data into the value of a cookie.
> If JavaScript writes data from a source into the `document.cookie` sink without sanitizing it first, an attacker can manipulate the value of a single cookie to inject arbitrary values.

###### Prevention

> To prevent cookie manipulation through the DOM, avoid dynamically writing to cookies using data from untrusted sources.

---

### JavaScript Injection

> JavaScript injection vulnerabilities arise when a script executes attacker controllable data as JavaScript.
>The sinks that lead to javascript injections:

```
eval() 
Function() 
setTimeout() 
setInterval() 
setImmediate() 
execCommand() 
execScript() 
msSetImmediate() 
range.createContextualFragment() 
crypto.generateCRMFRequest()
```

###### Prevention

> To prevent javascript injection through the DOM, avoid allowing data from untrusted sources to be executed as javascript.

---

### Document Domain Manipulation

> When a script uses attacker-controllable data to set the `document.domain` property.

> The `document.domain` property is used to enforce the [[Same Origin Policy (SOP)]], if two pages from different origins have the same `document.domain` property, they interact in unrestricted ways.
> If an attacker can change the `document.domain` property so that it matches that of a target website, then the target page can be fully compromised.

###### Prevention

> Avoid allowing data from untrusted sources to dynamically set the `document.domain` property.

---

### [[WebSockets]]-URL poisoning

> When a script uses attacker-controllable data as the target URL of a websocket connection.
> The `WebSocket` JavaScript constructor is a sink.

###### Prevention

> Avoid allowing data from untrusted sources to dynamically set the target URL of a websocket connection.

---

### Link Manipulation

>  When a script writes attacker-controllable data to a navigation target within the current page, such as a clickable link or the submission URL of a form.
> An attacker may be able to leverage this vulnerability to perform various attacks, including:
- Causing the user to be redirected to an arbitrary external URL, which could facilitate a phishing attack.
- Causing the user to submit sensitive form data to a server controlled by the attacker.
- Changing the file or query string associated with a link, causing the user to perform an unintended action within the application.
- Bypassing browser anti-XSS defenses by injecting on-site links containing XSS exploits. This works because anti-XSS defenses do not typically account for on-site links.

> The sinks responsible:
```
element.href 
element.src 
element.action
```

###### Prevention

> Avoid allowing data from any untrusted source to dynamically set the target URL for links or forms.

---

### Web Message Manipulation

> When a script send attacker-controllable data as a web message to another document within the browser.
> The web message data can be a source, by constructing a webpage that when visitied by a user, causes the users browser to a send a web message containing data that is under attacker's control.

> The `postMessage()` method for sending web messages can send data to the listener, this data is then sent to a sink on the parent page.
> The web message is the source that propagates malicious data to sinks.

> Take this script:
```javascript
<script>
window.addEventListener('message', function(e) {
	eval(e.data);
});
```
> This is the listener.
> If an `iframe` is constructed from a different origin that sends a message.
```HTML
<iframe src="website" onload="this.contentWindow.postMessage('alert()','*')" >
```
> What this does is that it sends a message with the content `alert()`, and it specifies that the message is sent to and accepted by any origin using `*`.

> Message contents is composed of structured data, such as strings, objects, arrays.
> Cannot send actual JavaScript or HTML tags and expect them to work, it depends on the sink that recieves them.
> Since it is the `eval()` function, then we can send JS code.
> Otherwise, we can try `Javascript:alert()`.

> Since the script event listener doesn't verify origin and the message is sent with `*`, then the message is passed to the sink, in this case, `eval()`.
> This will execute the javascript code. 
###### Prevention

> Avoid sending messages that contain data from an any untrsuted source.
> For sending cross-origin messaegs, the target window should be stated and specified.
> Verifying the origin of any incoming message.

---

### Ajax Request-Header Manipulation

> Ajax allows for asynchronous requests from websites to servers to dynamically change content without reloading.
> Ajax request-header manipulation vulnerabilities arise when a script writes attacker-controllable data into the request header of an Ajax request that is issued using an `XmlHttpRequest` object.

> The sinks are:
```
XMLHttpRequest.setRequestHeader() 
XMLHttpRequest.open() 
XMLHttpRequest.send()
jQuery.globalEval() 
$.globalEval()
```

###### Prevention

> Avoid allowing data from untrusted sources to dynamically set Ajax request headers.

---

### Local File-Path Manipulation

> This arises when a script passes attacker controllable data to a file handling [[Application Programming Interface (API)]] as the `filename` parameter.

- If the website reads data from the file, the attacker may be able to retrieve this data.
- If the website writes specific data to a sensitive file, the attacker may also be able write their own data to the file, which could be the configuration file of the operating system, for example.

> The sinks:
```
FileReader.readAsArrayBuffer() 
FileReader.readAsBinaryString() 
FileReader.readAsDataURL() 
FileReader.readAsText() 
FileReader.readAsFile() 
FileReader.root.getFile()
```

> Avoid passing data from untrusted sources to dynamically pass a filename to a file handling API.

---

### Client-Side [[SQL Injections]]

> When a script incorporates attacker-controllable data into a client-side SQL query in an unsafe way.
> Execute an arbitrary SQL query within the local SQL database of the user's browser.
> The sink is `executeSql()`.

###### Prevention

> Use parameterized queries (also known as prepared statements) for all database access.
> Parameterize also every variable data that is incorporated into database queries.

---

### HTML5-Storage Manipulation

> When a script stores attacker-controllable data in the HTML5 storage of the web browser.
> If the application later reads data back from storage and processes it in an unsafe way, an attacker may be able to leverage the storage mechanism to deliver other DOM-based attacks, such as [[Cross Site Scripting (XSS)]] and [[DOM Based Vulnerabilities#JavaScript Injection]].

> The sinks are:

```
sessionStorage.setItem()
localStorage.setItem()
```

###### Prevention

> Avoid allowing data from any untrusted source to be placed in HTML5 storage.

---

### Client-Side XPath Injection

> When a script incorporates attacker-controllable data into an XPath query.
> The sinks:

```
document.evaluate()
element.evaluate()
```

###### Prevention

> Avoid allowing data from untrusted sources to be incorporated into XPath queries.

---

### Client-Side JSON Injection

>  When a script incorporates attacker-controllable data into a string that is parsed as a JSON data structure and then processed.
>  Can be used to subvert the logic or cause unintended actions on behalf of the user.

> The sinks:

```
JSON.parse()
jQuery.parseJSON()
$.parseJSON()$
```

###### Prevention

> Avoid allowing strings containing data from untrusted sources to be parsed as JSON.

---

### Data Manipulation

> When a script writes attacker-controllable data to a field within the DOM that is used within the visible UI or client-side logic.
> An attacker may be able to leverage this vulnerability to perform virtual defacement of the website, such as changing text or images that are displayed on a particular page. 
> If the attacker is able to change the `src` property of an element, they could potentially induce the user to perform unintended actions by importing a malicious JavaScript file.

> The sinks:
```
script.src 
script.text 
script.textContent 
script.innerText 
element.setAttribute() 
element.search 
element.text 
element.textContent 
element.innerText 
element.outerText 
element.value 
element.name 
element.target 
element.method 
element.type 
element.backgroundImage 
element.cssText 
element.codebase 
document.title 
document.implementation.createHTMLDocument() 
history.pushState() 
history.replaceState()
```

###### Prevention

> Avoid allowing data from untrusted sources to be dynamically written to DOM-data fields.

---

### Denial of Service 

>  When a script passes attacker-controllable data in an unsafe way to a problematic platform [[Application Programming Interface (API)]], such as an API whose invocation can cause the user's computer to consume excessive amounts of CPU or disk space.
>  This may result in side effects if the browser restricts the functionality of the website, for example, by rejecting attempts to store data in `localStorage` or killing busy scripts.

> The sinks:
```
requestFileSystem()
RegExp()
```

###### Prevention

> Avoid allowing data from untrsuted sources to be dynamically passed to problematic platform APIs.

---

### Preventing DOM-based attacks

* Prevent data from untrusted sources to dynamically alter the value transmitted to a sink.
* Relevant data can be whitelisted, anything else is blocked.
* Encode/sanitize the data.

---
