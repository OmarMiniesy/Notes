
### General notes

> Service that assists administration of [[Docker]] containers

> Automatic deployment, scaling, and managing of containerized applications

> Supports services such as [[Elastic Load Balancer]], [[Elastic Block Storage (EBS)]] volumes, [[Elastic Cloud Compute (EC2)]] [[Security Services]] groups, and [[Security Services]] IAM roles.

___

### Task Definition

> Application requirements concerning the containers, such as cpu and memory for a task

Two types of task defintion creation:
1. Fargate: Prices based on task size
2. [[Elastic Cloud Compute (EC2)]] : prics based on resources used

___

### Cluster

> Set of containers runnin task requests in a certain region
> Default cluster is created with the first task definition

___

### Container Instance

> An [[Elastic Cloud Compute (EC2)]] instance registered into a cluster

___

### Container Agent

> Connects the container instance to the cluster, each container instance has a container agent

