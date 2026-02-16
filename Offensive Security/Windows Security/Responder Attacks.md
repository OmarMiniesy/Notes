### General Notes

A **Responder attack** is a credential harvesting technique where an attacker abuses Windows name resolution protocols to capture [[NTLM]] authentication hashes from machines on the same network.

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
