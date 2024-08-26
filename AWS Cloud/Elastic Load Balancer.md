### General Notes 

Distributes traffic across multiple servers, or compute resources.
- In the case of [[Elastic Cloud Compute (EC2)]] instances, a classic load balancer is used.
- There are multiple other types of load balancers for different resource types.

The main goal is to achieve optimum performance, and to guarantee that the data is present through required redundancy.
* **Performance** : If server starts acting up, load balancer adds another server.
* **Redundancy**: if server is lost, load balancer sends requests to other servers.

___
### Application Load Balancer (ALB)

Host different [[Application Programming Interface (API)]] endpoints of an application on different servers.
- Redirects the incoming [[HTTP]] traffic to the suitable server

___
### Network Load Balancer (NLB)

Balance the load on each [[Elastic Cloud Compute (EC2)]] instance by distributing the traffic amongst them.
- For example, by distributing the traffic between instances on different availability zones.

___
