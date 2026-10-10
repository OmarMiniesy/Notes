### General Notes

Data exfiltration is the process of moving data outside of an organization to a destination controlled by an adversary.
- This is unauthorized, and it is the act of stealing sensitive information from a network.
- Check out [[Detecting Exfiltration]]

Exfiltration can take place using several techniques & protocols:
- [[HTTPS]] & [[HTTP]]
- [[File Transfer Protocol (FTP)]] using legit servers, compromised creds, and non standard [[Port]]s.
- [[ICMP]]
- Encrypted [[Command and Control|C2]] channels
- [[Domain Name System (DNS)]]
- Cloud to cloud transfers
- DNS Tunnelling, check [[Detecting Tunneling]]
- base64 and chunk encoding
- steganography

To detect data exfiltration, host and network level indicators should be combined.
- **Network Based Indicators**:
	- Large `POST` requests
	- Uploads to cloud endpoints
	- Large amount of bytes to a single [[IP]]
	- Long DNS hostnames
	- DNS TXT queries
	- Unknown destination [[IP]]s or domains
- **Host Based Indicators**:
	- [[Sysmon]] `process create, 1`, `network connect, 3`, `file create, 11` events.
	- [[Windows Events Log]] `4663/4656` object access events.
	- `auditd` and `shell` history on Linux
	- Removeable media events.
	- Suspicious processes
	- Many file reads

---
