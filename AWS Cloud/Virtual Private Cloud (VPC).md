
### General Notes

1. Create own private network in the cloud.
2. Can launch services like [[Elastic Cloud Compute (EC2)]]
3. Spans all AZ (Availability Zones) in the region
4. Can control 
	* [[IP]] address ranges
	* subnets
	* [[Networking/Routing]] tables
	* network gateways

____

### Default VPC

* VPC in a default region, and has a public subnet for each Availability Zone
* It has the subnets, along with the route tables.
* The route tables have 2 rules
	* Internet facing communication
	* Internet gateway

___
