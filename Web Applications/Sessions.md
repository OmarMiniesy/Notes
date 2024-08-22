### General Notes

Stores information on the server side instead of the client side.
- This is to hide application logic, or to stop transferring [[Cookies]].
- Used to identify which [[HTTP]] requests are made by same user.

Since HTTP is a stateless protocol, request-response messages are unrelated to others, even if made by the same browser and the same user.
- Sessions were invented such that messages don't have to carry too much information all the time to identify the user.
- This session information is held in the client side of the HTTP protocol, or the browser.

> Session tokens are used as unique identifiers for web applications to identify users.

---
### Session IDs

Sessions are a mechanism that let the website store variables for a given visit on the server.
- Each session, for a user, is identified by a **session identifier (ID)** or token that the server assigns to the client.

Client can then present this ID to the server in every request, so the server recognizes the client.
- Server can retrieve the state of the client using this session ID. 
- Server stores session ID in text files.

> If an attacker manages to steal the session id of a user, then the attacker can impersonate the victims in the web applications. This attack is known as **Session Hijacking**.

Session ID security is based upon several factors:
1. **Validity Scope**: A session identifier should be valid for only one session only. That is, multiple sessions should not share the session ID.
2. **Randomness**: The more random and unique a session identifier is, the more secure the session is. This prevents the identifiers form being predicted or guessed.
3. **Validity Time**:  Web applications must define proper [Session Timeout](https://owasp.org/www-community/Session_Timeout) for a session token. If a web application does not define a session timeout, the session token would be valid infinitely, enabling an attacker to use a hijacked session effectively forever.

##### Storage

A critical security factor for session IDs is its storage location. There are several locations where they can be stored:
- **URL**: If the session identifier is stored in the URL, then the `referer` header can leak this value to other websites. This is because the `referer` header identifies from where the request was made, so if it is in the URL, then the header will contain this data. The *browser history* will also show the value of the identifier.
- **HTML**: If this data is stored in the HTML code of the webpage, then it can be identified in the cache memory, as well as any intermediate proxies that can inspect this code.
- `sessionStorage`: This is a browser storage feature that stores information as long as the page is open. If the page is closed, then this data is lost. However if the page is restored or refreshed, the data is still present.
- `localStorage`: This is also another browser storage feature that stores information. However, this storage is persistent, and can only be deleted by the user. This feature does not work in private windows or incognito tabs.
- [[Cookies]].

---
### Session [[Cookies]]

Session cookies contain single parameter value pairs referring to the session. These are found in the `set-cookie` header: 
* `SESSION=<session-ID>
* `PHPSESSID=<>` For PHP websites
* `JSESSIONID=<>` For JSP websites
* `ASP.NET_SessionID` For ASP.net websites.

> These session ids are used as an index in the server to get information related to that session.

Sequence of a login example:
1. Client login using POST request
2. Server sends response with `set-cookie` header field that contains the session ID
3. Browser then uses this cookie that contains the session ID for further requests

Session ID can also be transmitted via `GET` requests.

---

