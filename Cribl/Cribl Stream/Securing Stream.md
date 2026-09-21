### General Notes

Security files are created when [[Stream]] is installed.
- `users.json` - Contains the usernames and passwords for the authenticated users.
	- This file is tracked in Git
	- Found in `~/local/cribl/auth`
- `cribl.secret` - Contains an encrypted key that encrypts other keys like the passwords.
	- Unique to every installation.
	- This is tracked in Git.
	- Found in `~/local/cribl/auth`
- `keys.json` - The encryption keys that are encrypted by the secret are stored in this file.
	- This file is monitored for changes every 60 seconds.
	- Found in `~/local/cribl/auth`

---
### Recommendations

Use an **IDP**, or Identity Service Provider.
- This is used to allow Single Sign On and simplifies user authentication and authorization.
- Requires a license.

Use a **KMS**, or a Key Management Service.
- This is used to maintain the keys that [[Stream]] uses to encrypt secrets.
- Requires a license.

The GUI should be disabled for the worker nodes and the [[Edge]] nodes, as only the leader node should be used for changes and configurations.
- The stream leader GUI should be secured by using certificates.
- [[Transport Layer Security (TLS)]] is used in authentication for communication between the leader node and the workers.
	- worker to leader
	- source to worker
	- worker to destination
	- Leader GUI

---
