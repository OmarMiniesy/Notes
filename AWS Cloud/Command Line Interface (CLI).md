
### General Notes

> Access and control AWS account using command line

> Uses python

To use the CLI:
1. AWS CLI must be installed 
2. [[Security Services]] IAM users with admin privelages using
3. Configure AWS CLI

> Version of AWS running
``` bash
aws --version
```


>All AWS commands: [CLI Command Reference](https://docs.aws.amazon.com/cli/latest/reference/#available-services)
___

### 1. Installation - Linux


1. Download the installation file, `-o` renames the download file
```bash
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
```

2. Unzip the download file
```bash
unzip awscliv2.zip
```

3. Run the install program
```bash
sudo ./aws/install
```

4. Confirm installation
```bash
aws --version
```

Reference: [Installing or updating the latest version of the AWS CLI](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html)

___

### 2. IAM Admin User

1. Create user and choose the `Programmatic Access`
2. Attach existing policy and choose `Administrator Access`
3. Save the `Access key ID` and `Secret Access Key`

___

### 3. Configuration

1. Enter this command to configure the CLI

```bash
aws configure
```
or
``` bash
aws configure import --csv <path to csv file>
```

2. Enter the `access key ID` and `secret access key`
3. Choose the region and output format
4. If admin user access key is used, then enter 
```bash
aws configure set aws_session_token ""
```
5. If generated access key is used, then enter
```bash
aws configure set aws_session_token "<generated access key>"
```


> The access key is stored in `~/.aws/credentials` , check it out with `cat` command
> The profile is stored in `~/.aws/config` , check it out with `cat` command

> Change any of the parameters `aws configure set <parameter> <value>`

>If you already have a profile set locally, you can use `--profile <profile-name>` option with any of the AWS commands above. This will resolve the conflict with the existing profiles set up locally.

>View the current configuration
```bash
aws configure list
```

>View all existing profiles
```bash
aws configure list-profiles
```

> View the users
```bash
aws iam list-users
```

> Environment variables
```bash
export AWS_CONFIG_FILE=~/.aws/config
export AWS_SHARED_CREDENTIALS_FILE=~/.aws/credentials
```

> [Config Basics](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-quickstart.html)
> [Config and credentials](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html)
> [Environment variables](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-envvars.html)

___
