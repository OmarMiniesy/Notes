
### General Notes

> Service that monitors the [[Elastic Cloud Compute (EC2)]] instances and automatically adjusts by adding or removing instances based on given conditions to maintain availability and provide best performance

* included with [[Elastic Cloud Compute (EC2)]]
* automatically scales, adding new instances only when needed
* predictive scaling removes the need for manual adjustment 

> send a notification via [[Simple Notification Service (SNS)]] to tell user that an instance is being launched or terminated

___

### Auto Scaling Group

1. Count of EC2 instances
2. Launch Template: the configuration details for EC2 instances
3. Scaling Policy: defines how to scale the amount of instances