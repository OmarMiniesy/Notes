### General Notes

There are 4 deployment types for Cribl [[Stream]]:
- **Single Mode** - Run the leader node and worker node on single machine. Common for test environments and small environments..
- **Distributed Mode** - Leader node and worker nodes are on diff machines. One leader node manages worker nodes present in worker groups. Accommodates increased workloads.
- **Cribl Cloud** - quickly launch a stream instance with everything managed by Cribl.
- **Hybrid Approach** - Combines cloud and on-prem worker groups.

> This is a shared nothing architecture, where everything operates separately ensuring higher availability. 

Choosing which deployment types depends on:
- The amount of incoming data per unit of time.
- The amount of data processing that will happen on the incoming data. (routing, passing through, transforming?)
#### Leader High Availability

When leaders are configured, backup leader nodes should also be configured to ensure operations are not disrupted.
- The backup leaders should be configured with similar processing power and configurations to ensure smooth handling.
- The current state and metrics are stored in a Network File Storage (NFS) that is shared between the leaders. This data store is used to ensure that when a backup leader operates, it has the same context and understanding of the current operations.
- This is used in Cribl Cloud.

> Backup leaders should have Stream and Git installed, and copy private key information from the primary node to it to ensure communication remains stable.

##### Fault Tolerance & Reliability

A local Git repo is mandatory for any distributed [[Stream]] deployment.
- This git repo stores the configurations of the Stream deployment, done by the Leader node.
- There can also be a remote git repo that can be used for extra fault tolerance, this is recommended. This remote repo gets synced with the local repo.

In the case a Leader fails, a new leader should be created or ran from the pipeline of available leaders.
- This leader should have git installed and it pulls the necessary configuration from the remote repository.
- The leader is then restarted.

The steps for setting up the GitHub remote repo:

![[Architecture, 1.png]]

##### Recovering from a Crash
1. Download Cribl stream
2. Initialize git and attach to the remote repo with the configurations
3. Sync with the remote repo
4. Start this node as the new stream leader

![[Architecture, 2.png]]

---
### Different Topologies

One Leader, One Worker Group:
- simple deployment
- single department
- single location
- allows scaling out by adding more worker nodes to the same worker group

One Leader, Multiple Worker Group:
- larger and more complex deployment
- serving multiple departments and multiple locations
- allows addressing security concerns and regulations, and keeping data in house.

Stream Worker Group to Worker Group:
- Communication between worker groups is allowed.
- Allows data compression, secure communication, and can be viewed easily in a consolidated view.
- The source worker group configures a source, route, and destination (Cribl HTTP or Cribl TCP).
- The destination worker group configures a source (Cribl HTTP or Cribl TCP), route, and destination. 

---


