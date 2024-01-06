
### General Notes

> HyperText Transfer Protocol (HTTP).
> Application layer [[Protocol]].
> Client-Server [[Protocol]] to transfer web pages and web application data.

> HTTP connects to a web server such as Apache HTTP Server.
> Client sends requests and server sends back responses.
> Works on top of the [[Transport Layer]]'s TCP protocol.

> Its a clear text protocol, so it can be intercepted. 
> There is no authentication present between parties communicating.
> Therefore, to protect HTTP, [[HTTPS]] is used.

> HTTP is stateless, meaning that each request is completely unrelated to the ones preceding it/
> [[Cookies]] were created to make HTTP stateful.

> [HTTP Semantics](https://www.rfc-editor.org/rfc/rfc9110.html).

---

### HTTP Request

Format of HTTP request. 
```
VERB PATH VERSION
Headers \r\n
\r\n
Message Body \r\n
```
> `\r\n` same as enter on keyboard.

* The VERB specifies the type of action to be performed.  [HTTP Verbs](https://www.restapitutorial.com/lessons/httpmethods.html#:~:text=The%20primary%20or%20most%2Dcommonly,but%20are%20utilized%20less%20frequently.).
* The PATH specifies the path to the resource to be accessed. Can have query string after: `?id=1`.
* The VERSION specifies the HTTP version used.
* The Headers pass information between client and server. [List of Header Fields](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers).
* The Body contains paramters if any are sent. It can be empty.

---

### HTTP Response

> Contains the Status-Line which has the protocol version and the response code with its meaning.
> [HTTP Status Codes](https://www.restapitutorial.com/httpstatuscodes.html) : The response codes.

| Type  | Description                                                                                                                                 |
| ----- | -------------------------------------------------------------------------------------------------------------------------------- |
| `1xx` | Provides information and does not affect the processing of the request.                                                          |
| `2xx` | Returned when a request succeeds.                                                                                                |
| `3xx` | Returned when the server redirects the client.                                                                                   |
| `4xx` | Signifies improper requests from the client. |
| `5xx` | Returned when there is some problem with the HTTP server itself.                                                               |

---

### HTTP Verbs

#### Get
> Used to request a resource.
> `GET /page.php HTTP/1.1`

>Can pass arguments, add after the `?` character.
>`GET /page.php?name=mins HTTP/1.1`

#### Post
> Used to submit `HTML` form data.
> `POST /login.php HTTP/1.1`

> Can pass arguments only in the message body.
```
< Header >\r\n
\r\n
username=mins&password=mins
``` 

#### Head
> Requests the headers that would be returned if it was used with the `GET` verb.
> `HEAD / HTTP/1.1`

#### Put 
> Used to upload a file to the server.
> `PUT /path/to/destination HTTP/1.1`

> The file to be placed is put in the message body.
```
< Header >\r\n
\r\n
<PUT data>
```

#### Delete
> Used to delete a file from the server.
   `DELETE /path/to/destination HTTP/1.1`

#### Options
> Used to query the webserver for the enabled `HTTP` verbs.
> `OPTIONS / HTTP/1.1`

---

### HTTP Headers

Headers have a format of `header-name:header-value`.
> There can be multiple values for the same header.
##### General Headers
* Used in both responses and requests and are used to describe the message itself not its contents.

```
Date: ###
Connection: close or keep-alive
```

> The `connection` header is used to say if the network connection should terminate or stay on for further messages. Can be sent from either client or server to signify who wants to close and who wants to stay connected.

##### Entity Headers
* Used in both responses and requests and are used to describe the contents of the message (the entity).

```
Content-Type: text/html
Media-Type: application/pdf
boundary="b4e4fbd93540"
```
> `Content-Type` is automatically added by browser on client and is returned by server response.
> `Media-type` describes the data being transferred and is used by server to interpret input.
> `boundary` is used to separate multiple parts in one message. The value used above is used in forms.

##### Request Headers and Response Headers
* Request headers are used by clients, and response headers are used by servers.
* These do not relate to the message content.

##### Security Headers
* A list of response headers that define rules and policies to be followed by the browser while accessing the website and content.

```
content-security-policy
strict-transpot-policy
referrer-policy
```
> `content-security-policy` tells the browser to accept resources such as javascript scripts only from trusted domains. It controls the website policy towards external resources.
> `strict-transpot-policy` prevents the browser from accessing the website over regular HTTP, must be over [[HTTPS]].

---
