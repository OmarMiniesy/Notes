
### General Notes

> Stores information on the server side instead of the client side.
> This is to hide application logic, or to stop transferring [[Cookies]].
> Used to identify which [[HTTP]] requests are made by same user.

> Sessions are a mechanism that let the website store variables for a given visit on the server.
> Each session, for a user, is identified by a **session id** or token that the server assigns to the client.

> Client can then present this ID to the server in every request, so the server recognizes the client.
> Server can retrieve the state of the client using this session ID. 
> Server stores session ID in text files.

---

### Session Cookies

> Session cookies contain single parameter value pairs referring to the session.
> These are found in the `set-cookie` header
> Examples:
* `SESSION=<session-ID>
* `PHPSESSID=<>` For PHP websites
* `JSESSIONID=<>` For JSP websites
* `ASP.NET_SessionID` For ASP.net websites.

> These session ids are used as an index in the server to get information related to that session.

>Sequence of a login example:
1. Client login using POST request
2. Server sends response with `set-cookie` header field that contains the session ID
3. Browser then uses this cookie that contains the session ID for further requests

> Session ID can also be transmitted via GET requests.

---

