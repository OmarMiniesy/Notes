### Requirements

Supported OS:
- RedHat
- CentOS
- Ubuntu
- AWS Linux
- Suse Linux 

System requirements:
- 1GHZ processor
- 512MB RAM
- 5GB Disk space (more if using *Persistent Queuing*)

---
### Bootstrapping

By adding a new [[Edge]] node, we can configure settings and this will give us a script we can run on the edge node to configure it there.

> [[Port]] 443 should be open to communicate with the Cribl CDN and the [[Cribl Cloud]] leader node. If it is an on-prem leader node, then port 9000.

The script does the following:
- sets some variables
- determine the OS version
- adds the user
- downloads cribl edge and untars it
- configures edge by reading the `/local/_system/instance.yml` file in the cribl install directory.
- performs a `chmod` on the files and enables it to start on boot as a service.

> Running this as `sudo` sometimes helps certain steps to work, such as adding the user and running the service.

![[Deploying on Linux.png]]

---
### Considerations

The *configuration bundle* is a compressed archive of the configuration files and it is deployed by the leader to the node.
- It overrides changes at the node.

Make sure that the [[Firewall]]s allow communication between the edge node and the leader, and that all necessary ports are open.

---
