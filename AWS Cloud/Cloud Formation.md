
### General Notes

Model an entire infrastructure in a text file written in `json`.
- Cloud Formation designer can be used to create the templates, called stacks.

___
### Creating a Stack

Creating a stack that creates an [[Simple Storage Service (S3)]] bucket.

1. Designer tab, and drag a [[Simple Storage Service (S3)]] bucket
2. For the `json` properties, add this `json` code 
``` JSON
{
"AWSTemplateFormatVersion": "2010-09-09",
"Description": "Basic S3 Bucket CloudFormation template",
"Resources": {
"S3BucketCreatedByCloudFormation": {
 "Type": "AWS::S3::Bucket",
 "DeletionPolicy": "Delete",
 "Properties": {
   "AccessControl": "PublicRead"
 }
}
},
"Outputs": {
"BucketName": {
 "Value": {
   "Ref": "S3BucketCreatedByCloudFormation"
 },
 "Description": "Name of the newly created Amazon S3 Bucket"
}
}
}
```

3. Refresh the designer
4. validate template to check validity
5. Deploy stack
6. Delete stack after done for charges

---