### General Notes

This provides compute power and resources by creating a virtual computer.
- Choosing memory, operating system, and system resources.

They are essential servers provided for rent in the cloud using a "pay as you go" business model. 
- Therefore, make sure to stop or terminate when not in use to prevent payment.

> Can have extra storage by using [[Elastic Block Storage (EBS)]]

___
### How to Connect - Linux/Mac

1. Download the private key file  *.pem*
2. Open terminal in same location as *.pem* file

- Connect Via [[Secure Shell Protocol (SSH)]]
``` bash
ssh -i <path of private key file .pem> <user@public DNS>
```

`user`:  You will log-in using the default name. 
- The default username for Ubuntu instances is `ubuntu`, and for Linux, it is `ec2-user`
- Other usernames available here -> [usernames](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/connection-prereqs.html)

___
### Commands via [[Command Line Interface (CLI)]]

- The [[Elastic Cloud Compute (EC2)]] instances in the account
```bash
aws ec2 desribe-instances
```

- Start an [[Elastic Cloud Compute (EC2)]] instance (or stop `stop-instances` )
```bash
aws ec2 start-instances --instance-ids <instance id>
```

___


