
## ACL (Access Control List)

> Set of firewall rules for controlling traffic coming in and out of subnets in the [[Virtual Private Cloud (VPC)]]

###### **Inbound** and **Outbound** IPV4 traffic follows these rules created.

1. These rules are numbered and ordered
2. Lowest number rule evaluated first

> The rules compromise conditions, such as checking the IP of the sender.

___

## AWS WAF (Web Application Firewall)

> This is a [[Firewall]] that protects the web applications

> Protect application from common exploits by monitoring and controlling the requests.

>Can create Web ACL to monitor requests. This can protect [[CloudFront]] distributions.
___

## AWS Shield

>DDos attack detection and automatic mitigations. 

___

## AWS Firewall Manager

>Configure and manage firewall rules accross accounts and applications

___

## IAM (Identity and Access Management)

>Configure who can access the AWS account, the services, or the applications.
>Global service that gives permissions to **users, applications, or services.**

>IAM **user** is an entity that has a user and access credentials.

>IAM **group** is a colletion of users, making permission specification easy

> IAM **Security Group** is a built in firewall for [[Elastic Cloud Compute (EC2)]] instances.

>IAM **role** is an identity that has permissions and privileges, these are attached to users or groups

-   IAM user role: an IAM role can give a user a set of permissions to access one or more services.
-   IAM service role: an IAM role gives a service a set of permissions to access one or more services.

>Policy defines granular level permissions that can be attached.
>There are default policies, and policies can be created using `json`
>[Policies](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_examples.html)

> IAM **Policy Simulator** is an AWS service to check the effect of the policies
> IAM **Policy Generator** is an AWS service to generate policies

#### Creating a User

1. Programmatic access -> access id and secret key
2. attach policies to the user
3. Download the access key file `.csv` that will be used to access the AWS [[Command Line Interface (CLI)]].

> View the users via [[Command Line Interface (CLI)]]
```bash
aws iam list-users
```

#### Deletion
1. Detach policies from user
2. delete user
3. delete policies

> Deleting user using [[Command Line Interface (CLI)]]

1. Policies can be detached by identifying its `ARN`
``` bash
aws iam detach-user-policy --user-name <user-name> --policy-arn <arn>
```
* listing the policies of a user
``` bash
aws iam list-attached-user-policies --user-name <user-name>
```

2. Delete the access key by listing the access key id
``` bash
aws iam delete-access-key  --user-name <user-name> --access-key-id <akid>
```
* list the access key of the user
```bash
aws iam list-access-keys --user-name <user-name>
```

3. Delete the user
``` bash
aws iam delete-user --user-name <user-name>
```

___
