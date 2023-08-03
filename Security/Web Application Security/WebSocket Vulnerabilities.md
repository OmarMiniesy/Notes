### General Notes

> Any vulnerability that arises with regular [[HTTP]] can also arise for [[WebSockets]] communicating.
> Using [[Burp Suite]] to intercept and modify [[WebSockets]] messages, to replay and generate messages, and manipulate connections.

> User suppled input transmitted to the server as a message might be processed in unsafe ways leading to [[SQL Injections]] or [[XXE Injection]]s.
> If attacker controlled data is transmitted via WebSockets to other users, it can lead to [[Cross Site Scripting (XSS)]] attacks or client-side vulnerabilities.

---
### Manipulating WebSocket Messages

> Tampering with the contents of the [[WebSockets#WebSocket Messages]] are responsible for the majority of vulnerabilities.
> [[WebSockets]] usually transmit data in JSON format, so the value part of the transmitted data can contain a payload.

> To manipulate messages, intercept them as they are sent in [[Burp Suite]] proxy and modify them.
> This could bypass client-side [[Web Encoding]] and more security mechanisms.

---
### Manipulating WebSocket Handshake

> Some vulnerabilities can be found by manipulating the handshake, and they are caused by design flaws.

1. Too much trust in [[HTTP]] headers, such as `X-Forwarded-For`.
2. Flaws in handling [[Sessions]]. The session of messages is determined by the session of the handshake message.
3. Larger attack surface due to introduced custom [[HTTP]] headers.

---

### Securing WebSockets

* Using the `wss://` [[Protocol]].
* Hard code the URL of the websocket endpoint and don't include user-input data.
* Protect WebSocket handshake from [[CSRF]] to avoid cross-site hijacking.
* Treat data recieved on both sides of the connection as unclean and handle safely.

---

