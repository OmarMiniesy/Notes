### General Notes

Compute power in the cloud to execute code.
- It is useful as it is only called when it is needed, without the need to create a server computer.

No need to deploy an entire server if only a specific function is to be executed at very specific times when requested.
- Hence, this can be called a *FaaS*, or a Function as a Service.

> Can use the Serverless Repository that has a collection of Lambda functions written to be used by others.

___
### Lambda Functions

1. Code run on Lambda is called `Lambda function`.
2. Lambdas have 15 minute time limit.
3. Event-driven, such as uploading file to [[Simple Storage Service (S3)]] bucket or adding item to database such as [[Dynamo DB]], with events represented in `JSON` format.

``` JSON
"key" : "value";
```

4. Each function can get a max of 10 events.

___
### Languages Supported

* Java
* Go
* PowerShell
* [[NodeJs]]
* C#/.NET
* Python
* Ruby

>Custom runtimes can be made for languages that aren't supported.

___
### Billing

Billed only for compute time the function consumes.
- Recommended to delete functions and [[Security Services]] IAM roles after usage

---
