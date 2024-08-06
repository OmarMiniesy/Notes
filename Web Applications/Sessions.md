### General Notes

Stores information on the server side instead of the client side.
- This is to hide application logic, or to stop transferring [[Cookies]].
- Used to identify which [[HTTP]] requests are made by same user.

> Session tokens are used as unique identifiers for web applications to identify users.

Sessions are a mechanism that let the website store variables for a given visit on the server.
- Each session, for a user, is identified by a **session id** or token that the server assigns to the client.

Client can then present this ID to the server in every request, so the server recognizes the client.
- Server can retrieve the state of the client using this session ID. 
- Server stores session ID in text files.

Web applications must define  proper [Session Timeout](https://owasp.org/www-community/Session_Timeout) for a session token. 
- After the time interval defined in the session timeout has passed, the session will expire, and the session token is no longer accepted. 
- If a web application does not define a session timeout, the session token would be valid infinitely, enabling an attacker to use a hijacked session effectively forever.

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

