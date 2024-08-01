
### General Notes

Software composed of a server and a client.
- The backdoor server runs on the victim machine listening on the network and accepting connections.
- The client is on the attacker machine, and connects to the backdoor server.

---

### `NetBus` and `SubSeven`

Backdoors that allow the attacker to browse the victim hard drive, upload and download files, and execute programs.
- After a backdoor connection is in place, an attacker gets full remote control over the host.

> Can be blocked via [[Firewall]]s. 

---

### Connect-Back Backdoor

This a backdoor mechanism to bypass [[Firewall]]s.
- Instead of the normal backdoor, the machine being targeted acts as the client, and connects to the attacker machine (the server). 

> The attacker machine can then listen on a known [[Port]] such as 80.

---
