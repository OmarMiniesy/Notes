
### General Notes

> Send notifications to users
> Users must be subscribed

> Limited to 256 characters

> can send messages to users or other AWS services

Notifications can be sent using:
- Mobile Push
- Email
- Text Message / SMS

___

### Commands via [[Command Line Interface (CLI)]]


> Publish a message to a [[Simple Notification Service (SNS)]] topic
1. `sns` is the service
2. `publish` is the command
```bash
aws sns publish --topic-arn <arn> --message "<message>"
```
