### General Notes

Cribl Stream allows users to route data from any source to any destination.
- Can obtain data from any source and send it to any destination.
- Can perform processing on data in transit — see [[Pipelines, Functions, Packs]] and [[Routes]].
- [[Cribl Products#Cribl Edge|Cribl Edge]] can help send the data to Cribl Stream, or straight to the destination.
- [[Cribl Products#Cribl Search|Cribl Search]] allows searching on Cribl Edge or at the destination.

Cribl Stream:
- Single Mode: Run the leader node and worker node on single machine. Test environment.
- Distributed Mode: leader node and worker nodes are on diff machines. One leader node manages worker nodes present in worker groups.

Worker Groups are a set of worker nodes that share the same configuration.
- A group of machines that work together to process data.
- Worker groups are logical groupings of worker nodes that share the same configuration.
- Groups can be separated by location, data type, function, or dedicated processing workflows
- A worker group can have any number of worker nodes.

A leader node manages all the configs for the worker groups and [[Edge]] nodes, and sends the config information.
- Comm takes place by sending configs on how to collect data based on rules.
- The leader communicates via TCP [[Port]] `4200`.
	- This is used for heartbeats, metrics, and notification communications.
- Also uses [[HTTP]] port 4200 to download bundles and configuration distribution.
- 443 is done through Cribl Cloud.
- The leader does a lot of work, so it should be maintained and have the necessary processing power and resources to manage the traffic.

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

### Stream Projects

Gives administrators the ability to control access to data.
- Creates isolated spaces for teams and users to access data.
- Each project grants access to sources, destinations, pipelines, and more.
- Projects are scoped to a worker group.

**Project Editors**:
- Can adjust the data flow for the entire project.
- Can configure objects and commit changes to git.

**Cribl Admin**:
- Can create subscriptions and projects.
- Provides users with access to different projects.

**Subscriptions**
- Specify a subset of a worker group's data.
- Multiple subscriptions can be assigned to a single project.

**Projects**
- Connections between subscriptions and destinations.
- Multiple subscriptions and multiple destinations can be combined in one project.

---
