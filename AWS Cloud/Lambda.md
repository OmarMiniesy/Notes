
### General Notes

> Compute power in the cloud to execute code

___

### Lambda Functions

1. Code run on Lambda is called `Lambda function`
2. Lambdas have 15 minute time limit
3. Event-driven, such as uploading file to [[Simple Storage Service (S3)]] bucket or adding item to database such as [[Dynamo DB]], with events represented in `JSON` format 

``` JSON
"key" : "value";
```

4. Each function can get a max of 10 events

___

### Languages Supported

* Java
* Go
* Powershell
* Node.js
* C#/.NET
* Python
* Ruby

>Custom runtimes can be made for languages that arent supported

___

### Billing

> Billed only for compute time the function consumes
> Recommended to delete functions and [[Security Services]] IAM roles after usage