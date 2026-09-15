### General Notes

Standing up a worker node means bootstrapping a fresh machine so it registers with the leader and becomes a managed member of the distributed deployment. The leader's UI (under the worker group settings) provides a `curl` command that you copy and run directly on the worker machine. That command:
1. Downloads the Cribl Stream binary from the leader node.
2. Configures the worker with the leader's address so it knows where to report.
3. Starts the worker process in worker mode.

After this, the worker is registered under a worker group and receives all configuration from the leader — no individual configuration is needed on the worker itself.

For this to work, port 4200 and 9000 must be open between the leader and worker:

**Port 4200 (Leader-facing)**
- **TCP control channel**: The worker maintains a persistent TCP connection to the leader on port 4200. This is how the leader pushes configuration changes and deployment commands to workers in real time.
- **HTTP bundle download**: When a deployment is triggered, the worker fetches the full config bundle (a compressed archive of all pipeline, route, source, and destination configs) from the leader over HTTP on this same port.

**Port 9000 (Worker-facing)**
- The worker's own management API port. The leader connects back to the worker on this port for health checks, status queries, and reverse communication. Without this port open, the leader cannot confirm the worker is alive.

**Port 443**
- Used only on [[Cribl Products#Cribl Cloud|Cribl Cloud]]. Workers communicate to the Cribl-managed leader over standard [[HTTPS]] instead of port 4200.

Communication flow:
```
Worker ──── TCP 4200 ────► Leader   (registration + ongoing config sync)
Worker ◄─── HTTP 4200 ───  Leader   (config bundle download on deploy)
Leader ──── TCP 9000 ────► Worker   (health checks, status, reverse comms)
```

- Ports can be changed in `/opt/cribl/local/cribl/cribl.yml`.

### Installation

Recommend to install the application in the `/opt` directory.
- Create a `cribl` user to own all files and runs all processes. Should not be a privileged account.
- Worker nodes have randomly generated admin passwords. These can be accessed through the leader node for the administrative tasks.
- Provide minimal access and non-priv account to run cribl stream.
- Can start it on boot using `initd` or `systemd`.

Steps:
1. Add a cribl user:
```
sudo adduser cribl
```

2. Navigate to cribl:
```
cd /opt
```

3. Download Stream from cribl.io and extract:
```
sudo curl -Lso $(curl -s https://cdn.cribl.io/dl/latest) | sudo tar zxfv -
```

4. Change ownership of cribl and switch to the cribl user:
```
sudo chown -R cribl:cribl cribl
sudo su cribl
```

5. Enable boot start services from the `cribl/bin` directory:
```
cd cribl/bin
./cribl boot-start enable -m systemd -u cribl
```

6. start cribl and get the IP address of the leader node.
```
./cribl start
./cribl status
http://ip:9000
```

###### Settings

To select the stream architecture and modes for the machines, head to stream settings then global settings then distributed settings.
- Can select if it is a worker, leader, or edge.

To add worker nodes:
- log into leader node
- go to workers
- choose add/update worker node.
- Paste the script at the worker node. Should have the user created on the worker node.

**Logging In For The First Time**
- **Login:** The first login uses admin for both username and password. You will be prompted to create a new password upon login.
- **Registration:** Register with Cribl by providing basic information and accepting the license agreement
- **Deployment Type:** Set the deployment mode (Single Instance, Leader, or Worker) under Settings > Distributed Settings > General Settings.
    - Leader mode requires additional Worker Nodes for processing-intensive deployments and Edge node support.
    - Git installation on the Leader Node is mandatory for Leader mode.

---
