### General Notes

*Command and Control* (C2 or C&C) is the stage where an adversary communicates with the systems they have compromised to control them remotely.
- This is the [[MITRE ATT&CK]] tactic [Command and Control](https://attack.mitre.org/tactics/TA0011/), and a phase in the [[Cyber Kill Chains]].
- It works on an **agent/server** model: a small *implant* (or *beacon*) runs on the victim and checks in with a C2 *server* the attacker controls, asking for instructions and returning results.

The attacker uses the C2 channel to:
- Send commands and new tooling to the host. See [[Ingress Tool Transfer]].
- Receive output, stolen credentials, and exfiltrated data. See [[Data Exfiltration]].
- Control multiple hosts at once, such as a *botnet*. See [[Malware#Bots and Botnet]].

> The C2 server address, domain, or URI pattern is a *network artifact* on the [[Pyramid of Pain]] — painful for the attacker to change, so it is a valuable detection target.

---
### C2 Channels

Attackers tunnel C2 traffic inside common, trusted [[Protocol]]s so it blends in with normal traffic.
- **[[HTTP]] / [[HTTPS]]**: the most common. Commands are hidden in headers, cookies, or the body, and [[Transport Layer Security (TLS)|TLS]] hides the content from inspection.
- **[[Domain Name System (DNS)]]**: commands and data encoded into subdomain queries and responses. See [[Detecting Tunneling#DNS Tunneling]].
- **[[ICMP]]**: data smuggled inside the payload of ping packets. See [[Detecting Tunneling#ICMP Tunneling]].
- **Legitimate services**: using trusted platforms (social media, cloud storage, pastebin) as the C2 middleman so traffic looks normal.

> *Domain fronting* hides the real C2 destination behind a high-reputation domain (e.g. a CDN), so the traffic appears to go to a trusted service.

---
### Beaconing

*Beaconing* is the periodic check-in the implant makes to the C2 server.
- It is characterised by regular intervals, low volume, and repetitive connections to the same destination.
- Attackers add *jitter* (randomised delay) and *sleep* timers to break the regular pattern and evade detection.

> See [[Detecting Beaconing Malware]] for the indicators and how to hunt for them.

---
### C2 Frameworks

These are the tools attackers and red teams use to run C2 infrastructure:
- **Cobalt Strike**: commercial, the most widely abused; its implant is called a *Beacon*.
- **Metasploit / [[Meterpreter]]**: open source, common in testing.
- **Sliver, Empire, Mythic**: open-source frameworks that are popular C2 alternatives.

---
