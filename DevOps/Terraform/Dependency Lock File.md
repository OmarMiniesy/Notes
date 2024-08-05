### General Notes

[[Terraform]] uses external dependencies to manage the configurations. These external dependencies can be [[Resources]] or [[Providers]].
- These dependencies are independent, meaning they are updated and managed separately, requiring that some sort of *version control* needs to be implemented.

> There are **version constraints** that can be defined whilst writing the files using the [[Configuration Language]] which specifically state the versions of the resources to be called.

The **Dependency Lock File** is responsible for remembering the decisions made about the versions for these external resources.
- It basically stores the version numbers of these resources for any future calls or runs. 
- Similar to the dependencies section in the [[NodeJs]] `package.json` file.

> It is located in the working directory of the project, or the root module.

---
### `.terraform.lock.hcl`

The lock file belongs to the whole configuration project, not just a single module.

The lock file is updated automatically, and if not present, created, when the following command is run:
```terraform
terraform init
```
- Adding the `-upgrade` retrieves the latest versions 


> This file is not written in the terraform configuration language.

---
