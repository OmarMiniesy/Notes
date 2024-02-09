
### General Notes

> Used to create the [[Kubernetes Components]] in a [[Kubernetes]] cluster.

All configurations in the cluster go through the API server found in the master node. Configurations can be sent to the master node through the:
* UI (dashboard).
* [[Application Programming Interface (API)]]
* CLI (`kubectl`).

The requests to the API in the master node are either in `JSON` or `YAML` format, and these are the configuration files.

> The controller manager found in the master node is responsible to keep the state as defined by the blueprints in the configurations.

---

### Configuration file

These files are either written in `YAML` or `JSON`, and they are stored in the code repo, or in a repo that is made only for the configuration files.

> Configuration files for a cluster are usually found for every component.
#### Content

1. The `apiVersion` and `kind`:
	* Used to specify the version of the API and the type of [[Kubernetes Components]] used.
	* The API version is different per component.
2. The metadata:
	* The name of the component. Unique per pod.
	* Labels for the components. The same for all pod replicas.
1. The specs:
	* Kinds of configuration to be applied for the component.
	* These are specific to the `kind` found in the configuration file.
2. The status:
	* Added automatically by [[Kubernetes]], and is used to determine if what is actually running in the cluster is what is required.
	* Updated continously to monitor the cluster, and whenever a component dies, kubernetes acts.

> The status information comes from the `etcd` found in the master node.

---
