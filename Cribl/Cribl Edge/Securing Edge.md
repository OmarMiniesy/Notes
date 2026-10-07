### Installation

Create a user named `cribl` that is not root.
- This user is to be the one to downloaded edge.
- This user is to have access to the Cribl directory.

---
### Securing Communication

Make the [[Stream]] leader GUI secure with [[Certificates]].

Disable the [[Edge]] node GUI.

[[Transport Layer Security (TLS)]] is used to secure communication between Leader and edge nodes.
- This can also be mTLS.

---
### Log Collection

To be able to read logs from the edge node, access must be provided. This includes:
- If using `SELinux`, then set it in permissive mode.
- If using `AppArmor`, it should be configured to allow the logs to be accessed.
- The file system containing the logs should have the correct read permissions for the user.
- The folders that contain the logs should have their security groups configured to allow access.

To allow Files to be read using *File Monitor* source, the following permissions should be configured:
- Read privilege on the desired files.
- Execute privilege in necessary directories to traverse through.

> For the *Exec* source, additional permissions might be needed.



---
