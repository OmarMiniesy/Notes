
### General Notes 

> Distributes traffic across multiple servers and stands in front of a web server

> Works with [[Elastic Cloud Compute (EC2)]], containers, IP addresses, and [[Lambda]] functions

* Performance : If server starts acting up, load balancer adds another server 
* Redundancy: if server is lost, load balancer sends requests to other servers

___

### Application Load Balancer (ALB)

> Host different [[Application Programming Interface (API)]] endpoints of an application on different servers
> Redirects the incoming [[HTTP]] traffic to the suitable server

___

### Network Load Balancer (NLB)

> Balance the load on each [[Elastic Cloud Compute (EC2)]] instance by distributing the traffic amongst them.
> If 2 instances are on 2 different Availability Zones

___

### Classic Load Balancer (CLB)

> Balances load across different [[Elastic Cloud Compute (EC2)]] instances

___
