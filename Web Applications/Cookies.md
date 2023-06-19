
### General Notes

> Created to make [[HTTP]] [[Protocol]] stateful.
> They are textual information installed by a website into the Cookie Jar of the **browser**.
> Cookie Jar is storage space where web browser stores cookies.
> Storing data on the client side instead of the server side ([[Sessions]]).

> Can be viewed in JavaScript using `document.cookie`

---

### Cookie Format

> Server can set cookie via the `Set-Cookie` HTTP header in a response message
> Cookies contain the following data:
* Cookie Content: Text Key-Value pairs that contain data
* Expiration Date
* Path: sends the cookies to all subsequent requests to this path and everything under it.
* Domain
* HTTP Only Flag: only HTML technology can read the cookie. Secure against [[Cross Site Scripting (XSS)]].
* Secure Flag: Cookies are only sent over [[HTTPS]]

> Cookies are sent to the valid domain and path and only when they are not expired and according to the flags.
> If domain is not set, the Host-only flag is set, and cookie is only sent to the exact hostname. The domain becomes set to the hostname.

---

### Cookie Protocol

> Login Example: 
1. Browser sends a POST request with username and password
2. Server sends a response with a `set-cookie` header to tell the browser to install the cookie
3. For every further request, the browser considers the cookie data and flags
4. If the checks pass, then a cookie will be inserted in the header of the browser request

> What this does, is that the browser now manages to maintain a stateful connection to the server, meaning that all subsequent requests dont need authentication again.

---
