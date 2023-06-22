
### General Notes

> Allows an attacker to control the content of a web application.
> Can target the application users.

> When a web application uses unfiltered user input to build content.
> Attackers can control the output HTML and JavaScript.

> Can steal other user [[Cookies]], or impersonate other user [[Sessions]].

> XSS involves injecting malicious code in the output of the page that is then rendered by users of that page.

---

### Finding XSS

> Look at every user input, and test if it's displayed as output.
> Try injecting HTML tag to see if the HTML is interpreted: `<i>, <h1>`.
> Try injecting JavaScript: `<script>alert('XSS')</script>`

> To exploit the XSS, there are different types of attacks:
1. Reflected.
2. Persistent.
3. DOM Based.
4. Dangling Markup.
---

### Reflected XSS Attacks

> When the payload is carried inside the request that the user (victim) browser sends to the vulnerable website.
* Example: A link to a website with an embedded payload. `http://victim.site/search.php?find=<payload>`.
> Use the simple payload as proof of concept.
```
<script>alert("XSS")</script>
```

> Called reflected because an input field of the [[HTTP]] request sent gets immediately reflected as output in the immediate response of the browser.
> There are reflected XSS filters built now to counter such attack.

---

### Persistent XSS Attacks

> When the malicious payload is sent to the webserver and **stored** there.
> When a webpage then loads, it pulls this payload from the server and the malicious code is displayed within the HTML output.

>Common in HTML forms where users submit content to the webserver and then is displayed back to users.
* Common sections
* User profiles
* Forum posts

---

### DOM-Based XSS

> When javascript takes data from the attacker and passes it to a sink that supports dynamic code execution.
> Such as the URL, which is passed with the `window.location` object.
> Can be found using [[Burp Suite]] web vulnerability scanner.

> The Sink is the portion of code where the payload is entered and executes the attack.
> There is a DOM vulnerability if there is an executable path through which data moves from source to sink.


##### HTML Sinks
> Testing for DOM-based means including alphanumeric strings and checking where it appears in the HTML of the webpage.
> Identify the HTML context, and try constructing a payload that breaks out.
> Adding an extra `"` to break out of the existing tag maybe, or `>` to break out.


#### JavaScript Execution Sinks
> Use the JavaScript debugger to test how the input was sent and interpreted by the sink.
> Identify the JavaScript context, and look at the different variables and areas that the data moves to.
> Try to form a payload that exits or adds another element or tag.

```
"> < svg onload = alert(1) >
```

> Sometimes, we can introduce errors, and then call the onerror attribute with the payload.
```
<img src=1 onerror=alert(1)>
```

---

### [[Cookies]] Stealing With XSS

> JavaScript can only access [[Cookies]] if the `HttpOnly` flag is disabled. 
> Cookies can be displayed with `<script>alert(document.cookie)</script>`.

---

### Preventing XSS Attacks

1. Filter input on arrival
2. Encode data on output
3. Use appropriate response headers
4. Content Security Policy (CSP)

---
