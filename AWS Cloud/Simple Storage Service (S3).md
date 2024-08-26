
### General Notes

Object storage system in the cloud.
- Instances are called S3 buckets.
- Files in the bucket can be accessed, and in the properties tab their URL can be found.

> S3 Glacier used to hold data archives, which has higher latency but is cheaper than S3 buckets.

___
### Bucket Creation

Must name be unique worldwide, no spaces, no uppercase. 
- Convention `my-accountid-bucket`.
- Public buckets are used for hosting websites so that they can be publicly readable.

___
### Properties

*  **Bucket Versioning**: duplicates of object in the same bucket.
*  **Encryption**: Encrypt files stored in the bucket.
*  **Object Lock**: Prevent files being deleted or modified.
*  **Static Website Hosting**: Bucket used to host website.

___
### Commands Via [[Command Line Interface (CLI)]]


- Create public bucket 
``` bash
aws s3api  create-bucket --bucket <bucket-name> --acl public-read-write --region <region> --profile <profile-name>
```

- Add file to bucket
``` bash
aws s3api put-object --bucket <bucket-name> --key <file-name> --body <file-path> --profile <profile-name>
```

- Delete content in bucket then delete bucket
``` bash
aws s3api delete-object --bucket <bucket-name> --key <file-name>
aws s3api delete-bucket --bucket <bucket-name> --profile <profile-name>
```

- List items in a [[Simple Storage Service (S3)]] bucket
```bash
aws s3 ls s3://<bucket-name>
```

___
