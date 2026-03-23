### General Notes

A **Responder attack** is a credential harvesting technique where an attacker abuses Windows name resolution protocols to capture [[NTLM]] authentication hashes from machines on the same network.
- This hash can the be cracked or relayed to other systems to gain access with these credentials.

Windows systems try multiple name resolution methods when a hostname cannot be resolved in the following order based on the failure of the previous:
1. [[Domain Name System (DNS)]]
2. **LLMNR (Link-Local Multicast Name Resolution)**
3. **NBT-NS (NetBIOS Name Service)**

**LLMR** and **NBT-NS** are insecure, and poisoning take place when the following sequence occurs:
- A victim device sends a name resolution query for a mistyped hostname (e.g., `fileshrae`).
- [[Domain Name System (DNS)]] fails to resolve the mistyped hostname.
- The victim device sends a name resolution query for the mistyped hostname using LLMNR/NBT-NS.
- The attacker's host responds to the LLMNR (UDP 5355)/NBT-NS (UDP 137) traffic, pretending to know the identity of the requested host. 
- This effectively poisons the service, directing the victim to communicate with the adversary-controlled system.
- The result is that the attacker acquires the victim's [[NTLM#NTLMv2, Net-NTLMv2|Net-NTLM]] hash, which can be cracker or relayed again so the attacker impersonates the victim.

> Typically, attackers employ the [Responder](https://github.com/lgandx/Responder) tool to execute LLMNR, NBT-NS, or mDNS poisoning.

---
### Detecting Responder Attacks

[[Sysmon]] event ID `22` can be used to track [[Domain Name System (DNS)]] queries with incorrectly typed file shares or services.
```
index=main EventCode=22 
| table _time, Computer, user, Image, QueryName, QueryResults
```

Can also use [[Windows Events Log]] with Event ID `4688` to look for logons with explicit credentials.
- This can be used to check if the attacker used the stolen credentials to login to file shares.
```
index=main EventCode IN (4648) 
| table _time, EventCode, source, name, user, Target_Server_Name, Message | sort 0 _time
```

