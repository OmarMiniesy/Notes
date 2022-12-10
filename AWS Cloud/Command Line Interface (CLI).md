
### General Notes

> Access and control AWS account using command line

> Uses python

To use the CLI:
1. AWS CLI must be installed 
2. [[Security Services]] IAM users with admin privelages using
3. Configure AWS CLI

___

### 1. Installation

Refer to [[AWS CLI]]

___

### 2. 

___

### Commands

> Version of AWS running
``` bash
aws --version
```

> The [[Elastic Cloud Compute (EC2)]] instances in the account
```bash
aws ec2 desribe-instances
```

> Start an [[Elastic Cloud Compute (EC2)]] instance (or stop `stop-instances` )
```bash
aws ec2 start-instances --instance-ids <instance id>
```

> Publish a message to a [[Simple Notification Service (SNS)]] topic
1. `sns` is the service
2. `publish` is the command
```bash
aws sns publish --topic-arn <arn> --message "<message>"
```

> Send a message to the [[Simple Queue Service (SQS)]] queue in the account
1. `sqs` is the service
2. `send-message` is the command
```bash
aws sqs send-message --queue-url <url> --message-body "<message>" --message-group-id "<gid>" --message-deduplication-id "<ddid>"
```

> List all messages in the [[Simple Queue Service (SQS)]] queue in the account
```bash
aws sqs receive-message --queue-url <url>
```

> List items in a [[Simple Storage Service (S3)]] bucket
```bash
aws s3 ls s3://<bucket-name>
```


>All AWS commands: [CLI Command Reference](https://docs.aws.amazon.com/cli/latest/reference/#available-services)

___

