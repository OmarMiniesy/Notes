
### General Notes

Message queuing service to send, store, and receive messages through [[Simple Notification Service (SNS)]] or trigger [[Lambda]] functions.
- Unlimited number of transactions per second

FIFO queues are processed in the exact order, and each message is sent once.
- Up to 3_000 messages per second with batching or 300 messages per second without batching.

___
### Commands via [[Command Line Interface (CLI)]]

- Send a message to the [[Simple Queue Service (SQS)]] queue in the account.
```bash
aws sqs send-message --queue-url <url> --message-body "<message>" --message-group-id "<gid>" --message-deduplication-id "<ddid>"
```
1. `sqs` is the service
2. `send-message` is the command

- List all messages in the [[Simple Queue Service (SQS)]] queue in the account.
```bash
aws sqs receive-message --queue-url <url>
```

---
