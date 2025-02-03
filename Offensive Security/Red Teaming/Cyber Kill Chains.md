### General Notes

It describes the steps attackers follow to breach a system, from reconnaissance to achieving their objective.
- Understanding the kill chain allows organizations to identify and disrupt attacks at various stages, enhancing their security posture.

There are several Kill Chains present, examples include:
- [Lockheed Martin Cyber Kill Chain](https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html)
- [Unified Kill Chain](https://unifiedkillchain.com/)
- [Varonis Cyber Kill Chain](https://www.varonis.com/blog/cyber-kill-chain/)
- [Active Directory Attack Cycle](https://github.com/infosecn1nja/AD-Attack-Defense)
- [[MITRE ATT&CK FRAMEWORK]]

---

### Kill Chain Components

|Technique|Purpose|Examples|
|---|---|---|
|Reconnaissance|Obtain information on the target|Harvesting emails, OSINT|
|Weaponization|Combine the objective with an exploit. Commonly results in a deliverable payload.|Exploit with backdoor, malicious office document|
|Delivery|How will the weaponized function be delivered to the target|Email, web, USB|
|Exploitation|Exploit the target's system to execute code|MS17-010, Zero-Logon, etc.|
|Installation|Install malware or other tooling|Mimikatz, Rubeus, etc.|
|Command & Control|Control the compromised asset from a remote central controller|Empire, Cobalt Strike, etc.|
|Actions on Objectives|Any end objectives: ransomware, data exfiltration, etc.|Conti, LockBit2.0, etc.|

---
