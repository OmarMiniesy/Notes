
### General Notes

> Message queuing service to send, store, and recieve messages through [[Simple Notification Service (SNS)]]
> or trigger [[Lambda]] functions

> FIFO queues are processed in the exact order, and each message is sent once
> Up to 3_000 messages per second with batching or 300 messages per second without batching

> Standard queues offer best-effort ordering.
> unlimited number of transactions per second

___

### Commands via [[Command Line Interface (CLI)]]


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
