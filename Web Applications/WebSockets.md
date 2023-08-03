### General Notes

> Bi-directional full duplex communication [[Protocol]] initiated over [[HTTP]].
> Used for streaming data and asynchronous traffic.

> Differently from [[HTTP]], where there are responses and requests in a transcation-like manner, WebSockets are long-lived, and messages can be sent at any time in any direction.
> The connection stays open/idle until client/server sends a message.

> Used when low-latency or server-initiated messages are required.
> [[WebSocket Vulnerabilities]].

---
### Establishing Connections

> Connections are created using client-side JavaScript.
```javascript
var ws = new WebSocket("wss.//website.com/chat")
```
> `wss` [[Protocol]] establishes websocket over encryped TLS([[Transport Layer]] Security) connection, while `ws` uses an unencrypted connection.

###### WebSocket Handshake
> The browser and server then perform a WebSocket handshake over [[HTTP]].

1. The request: 
```
GET /chat HTTP/1.1 
Host: website.com 
Sec-WebSocket-Version: 13 
Sec-WebSocket-Key: wDqumtseNBJdhkihL6PW7w== 
Connection: keep-alive, Upgrade 
Cookie: session=KOsEJNuflw4Rd9BDNrVmvwBF9rEijeE2 
Upgrade: websocket
```

2. The response:
```
HTTP/1.1 101 Switching Protocols 
Connection: Upgrade 
Upgrade: websocket 
Sec-WebSocket-Accept: 0FFP+2nmNIf/h+4BP36k9uzrYGk=
```

> The headers used:
1. `Connection` and `Upgrade` indicate this is a websocket handshake.
2. `Sec-WebSocket-Version` specifices the protocol version.
3. `Sec-WebSocket-Key` contains a Base64 encoded random value that is randomly generated in each request.
4. `Sec-WebSocket-Accept` is a hash of the value submitted in the `Sec-WebSocket-Key`, concatenate with a string defined in the protocol specification. Done to prevent misleading responses from any misconfiguration.

---

### WebSocket Messages

> Messages are sent asynchronously in either direction.

* From client using JavaScript: 
``` javascript
ws.send(" hello world ");
```

> Data of any format can be sent, but JSON is used for structured content.

```JavaScript
ws.send({"message":"hello world"});
```

---
