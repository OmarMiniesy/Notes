### General Notes

This is a SaaS version of Cribl [[Stream]] and simplifies deployment.
- A leader and worker nodes are placed in the cloud.
- Cribl takes on the responsibility of managing and configuring the infrastructure.
- Cloud simplifies deployment.
- Allows quick expansion.
- pay for what you use.
- There is git enabled to push/commit.
- There is an owner account that can be used to give privileges to other users.

> Enables hybrid deployments to put worker nodes and edge groups on prem or in certain locations. The leader is on the cloud.

![[Cribl Cloud.png]]

##### Cribl Members
This is used to give access to users, worker groups, edge fleets, search and lake datasets.
- Granular access with RBAC.

Cribl Teams can be used to give access on team level.

---
### Default Sources & Ports

There is a list of pre-enabled [[Port]]s and [[Sources, Destinations, Collectors#Sources|Sources]].
- Ports `20000`-`20010` are open for configuration.
- [[Transport Layer Security (TLS)]] encryption is enabled, and authentication is left on the protocol layer.
- **mTLS** is not yet supported

---
### Access Control Lists

These can be used to provide [[IP]] ranges to restrict access for clients and sources.
- This also controls access to Cribl Cloud workers, but not to Hybrid or customer managed workers.

---
### Hybrid Deployments

Hybrid deployments enable placing the leader node on the cloud, while leaving the worker groups anywhere, so on prem, on the cloud, or hybrid cloud deployments.
- Hybrid workers must be assigned to different worker groups than cribl managed worker nodes.
- Port 4200 is used to communicate with the leader, so it should be open.

---
### Workspaces

This is basically creating isolated instances of operation for [[Stream]], [[Edge]], and [[Lake]] for different teams, projects, and so on.
- Is managed centrally through one portal.
- Logically segregated and dedicated configurations.
- Role based access.
- Allows packs to be easily moved between workspaces.
- There is a maximum of 5 workspaces.

---
### Connected Environments

Allows connecting on prem to cloud deployments and is managed by a single management instance.
- Uses Cribl credits.
- Provides access to cloud only features.

---
