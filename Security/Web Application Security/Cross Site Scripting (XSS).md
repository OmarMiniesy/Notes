
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

---

### Reflected XSS Attacks

> When the payload is carried inside the request that the user (victim) browser sends to the vulnerable website.
* Example: A link to a website with an embedded payload. `http://victim.site/search.php?find=<payload>`.

> Called reflected because an input field of the [[HTTP]] request sent gets immediately reflected as output.
> There are reflected XSS filters built now to counter such attack.

---

### Persistent XSS Attacks

> When the malicious payload is sent to the webserver and **stored** there.
> When a webpage then loads, it pulls this payload from the server and the malicious code is displayed within the HTML output.

>Common in HTML forms where users submit content to the webserver and then is displayed back to users.s
* Commen sections
* User profiles
* Forum posts

---

### [[Cookies]] Stealing With XSS

> JavaScript can only access [[Cookies]] if the `HttpOnly` flag is disabled. 
> Cookies can be displayed with `<script>alert(document.cookie)</script>`.

---
