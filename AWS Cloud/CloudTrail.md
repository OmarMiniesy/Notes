
### General Notes

> Audit and log everything that happens in the AWS account by recording all API calls.

Provides an event history: 
-   who has logged in
-   services that were accessed
-   actions performed
	- through the management console
	- SDK's 
	- command line tools
-   parameters for the actions
-   responses returned

> Have up to 5 cloud trails per region
> stores for up to 90 days

> Logs can be stored in [[Simple Storage Service (S3)]] buckets or delivered to CloudWatch

___

### Important 

>Remember, that the first trail does not attract billing charges. However, you incur charges for the [[Simple Storage Service (S3)]] bucket that will store your logs. You can create additional trails on a charge-basis.

___
