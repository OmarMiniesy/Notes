
### General notes

Service that deploys webapp and handles all the necessary other services such as [[Elastic Cloud Compute (EC2)]], [[Virtual Private Cloud (VPC)]], and the storage in [[Simple Storage Service (S3)]] buckets.
- As this service is *elastic*, it can add and remove resources as it sees fit to meet performance requirements.

This service provides a layer of abstraction that helps developers achieve their goals and launch applications without going through the hassle of configuring everything.

> It is called an *orchestration service*, or a *PaaS*, Platform as a Service.

___