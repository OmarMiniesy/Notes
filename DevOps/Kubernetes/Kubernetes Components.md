
### General Notes

These are the main [[Kubernetes]] components that formulate a cluster.

> These components are given knowing that a node is known. Nodes are machines in the cluster.

---
### Pod

The smallest unit in kubernetes, and it is an abstraction of a [[Container]]. Pods are entities found in nodes.

> Kubernetes abstracts the container technology, and allows for interaction in a high level manner with the kubernetes layer.

A pod is usually application specific, so it runs ones container at a time. 
* It can be the case with multiple containers, but their goal is very tightly coupled.

> Pods can communicate together using private [[IP]] addresses given to them inside a node. 
* Since pods can die easily, their IP address is changed on restart. This is problematic, as it affects all other pods that want to reach this pod.
* Kubernetes offers **service**, which can solve this issue and allows consistent communication.

---

### Service

Used to give permanent static IP addresses to pods.
* Regardless of pod lifetime, the service maintains the same [[IP]] address.
* This is used by pods to communicate together.

> Services also act as load balancers, sending the requests to the least busy pods.

There are different types of service:
* External service.
	* Allows the pod to communicate with external sources.
	* This can be used for example by the pod responsible for the frontend.
* Internal service.
	* This is the default service type, and only allows communication within the node.

The service's path is a URL, and it works by specifiying a [[Protocol]], path, and [[Port]].
```
http://<my-app>:<port>
```

This wouldn't be suitable for an application to be accessed from the outside, which is where kubernetes **Ingress** steps in.

---

### Ingress

This is a component placed onto the node, and it forwards the traffic from the outside and into the node's pods, routing it to the destination service.

> Ingress allows for a secure [[Protocol]], such as [[HTTPS]], and a better looking URL with a domain name.

---

### ConfigMap

This is a kubernetes component that holds external configuration data for services found in the pods.

> This is like the environment variables in a project.

This componenet allows for changes in this file during run time, and changes are updated real time. There is no need to rebuild the project after changing data in that componenet.

> Data in this file are stored in clear text, that is publically available.

---

### Secret

This a [[Kubernetes]] component similar to ConfigMap, but it holds data that is considered private.
* Usernames and passwords of the database for example.
* certificates.

> Similar to configmap, this componenet is used by pods to allow the pod to read and see the data in the pods.

---

### Volume

This component is used to store data for pods to contain persistent data. Done by attaching a storage solution to a pod (either internal or external).
* The data is persistent, meaning if the pods closes, the data still exists.

> Kubernetes doesn't manage persistent data. 

---

### Deployment

A [[Kubernetes]] component that helps defines blueprints for pods. This is another form of abstraction over the pod.
* Used to abstract over the pod layer, allowing the developer to create multiple pods and spawn several instances of each.

The deployment component allows for replication of pods, and these pods are to be connected via the same service.
* The pods get the same IP address.
* The service can load balance between the pods.
* If one pod fails, the other pod is used.

---

### StatefulSet

Since databases and data stores shouldn't be replicated because this can create consistency issues, the StatefulSet component is used to host such database applications.

> Used instead of the deployment component to achieve the same goal of replication and load balancing.

Its setup is difficult, which is why data stores and datasets are usually set up outside the [[Kubernetes]] cluster.

---
