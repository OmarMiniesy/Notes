
### General Notes

> HyperText Transfer Protocol (HTTP)
> Application layer [[Protocol]] 
> Client-Server [[Protocol]] to transfer web pages and web application data

> HTTP connects to a web server such as Apache HTTP Server
> Client sends requests and server sends back responses
> Works on top of the [[Transport Layer]]'s TCP protocol

> Its a clear text protocol, so it can be intercepted. 
> There is no authentication present between parties communicating.
> Therefore, to protect HTTP, [[HTTPS]] is used.

> HTTP is stateless, meaning that each request is completely unrelated to the ones preceding it
> So [[Cookies]] were created to make HTTP stateful

---

### HTTP Request

> Format of HTTP request
```
Headers \r\n
\r\n
Message Body \r\n
```


##### Header
> Header contains a request followed by some header fields.

>  Request has a verb from these  [HTTP Verbs](https://www.restapitutorial.com/lessons/httpmethods.html#:~:text=The%20primary%20or%20most%2Dcommonly,but%20are%20utilized%20less%20frequently.)
>  After the verb, the path requested and the protcol version is stated: `verb /path HTTP/<version>`. Example: `GET / HTTP/1.1`

> Header field has format `header-name: header-value`


##### Body
> Can be empty. There must be 2 empty lines after the header.
> Contains parameters if any are to be sent.

---

### HTTP Response

> Contains the Status-Line which has the protocol version and the response code with its meaning.
> [HTTP Status Codes](https://www.restapitutorial.com/httpstatuscodes.html) : The response codes

---

