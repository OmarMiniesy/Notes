
### General Notes

Send notifications to users or other AWS services that are subscribed.
- Limited to 256 characters.

Notifications can be sent using:
- Mobile Push
- Email
- Text Message / SMS

___
### Commands via [[Command Line Interface (CLI)]]

Publish a message to a [[Simple Notification Service (SNS)]] topic
```bash
aws sns publish --topic-arn <arn> --message "<message>"
```
1. `sns` is the service
2. `publish` is the command

---
