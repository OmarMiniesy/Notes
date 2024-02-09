
### General Notes

This is an open source *container orchestration tool*. These can be [[Docker]] [[Container]]s or other types of containers.

> Kubernetes can manage these containers and in large numbers, and in different environments:
* Virtual machines.
* Physical machines.
* Cloud environments.
* Hybried environments.

Kubernetes guarantees the following:
* High availability; no downtime.
* High scalability; performance varies with load.
* Disaster recovery; backups and restorations.

> A kubernetes system is also called a **cluster**.

---
### Architecture of the Cluster

##### Overview
The cluster is composed of:
* A master node. (At least 1, 2 in production)
	* Runs several kubernetes processes required for functionality.
* Worker nodes.
	* These have the applications that we want to run.
* Virtual network.
	* Allows the master nodes to talk to the worker nodes.
##### Master Node (Control Plane)

The master node has several process that are essential to ensure that the cluster operates correctly.

1. [[Application Programming Interface (API)]] server [[Container]].
* The entry point to the cluster for the different clients.
* These clients are the kubernetes UI, API, CLI. 
> The UI is used by the kubernetes dashboard and the API is used by scripts to automate tasks.
* Important for the [[Kubernetes Configuration]].

2. The Controller Manager.
* Keeps track and monitors the cluster.
* Restarts containers and repairing damages.

3. Scheduler.
* Intelligent process that distributes the workload onto the worker nodes based on needs, consumption, and resources.

4. `etcd`
* This is a key-value storage.
* Holds the configuration data, status data, and recovery snapshots of the cluster.

> In production environments, there are at least 2 master nodes backups ready to take on the leader role to not lose the cluster.

##### Worker Nodes (Node)

> Each node has a kubernetes process called a **kubelet**.

The kubelet is a process that allows the nodes to communicate together in the cluster, as well as executing tasks.

##### Virtual Network

> Allows communication between the master node and the worker nodes.

Turns all of the nodes inside a cluster to one powerful machine with the combination of all their resources.

---
