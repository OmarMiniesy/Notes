### General Notes

This is an [[(IAC) Infrastructure as Code]] tool that automates the handling and management of the necessary configuration files.
- Done through the [[Configuration Language]].

> A tool for building, changing, and versioning infrastructure efficiently.

Terraform can create and manage resources by communicating with other services and vendors through [[Application Programming Interface (API)]]s. 
- AWS, Azure, google cloud, [[Kubernetes]], GitHub, and [more](https://registry.terraform.io/).

Terraform works in 3 stages:
1. Writing the configuration files, this contains all the needed infrastructure with their specifications.
2. A plan is created that will outline the execution to go from the current state to the desired state.
3. The plan is executed given approval, and the resources are created and provisioned, and dependencies are respected in the execution.

---
### Files and Modules

A **module** is a collection of `.tf` files kept together in a directory.
- Nested directories are separate modules.

> Files are saved using the `.tf` extension.

All the files that comprise the module are grouped together and can be considered a single document.

> There is always a root module, and there can only exist one instance of it.

A terraform configuration is complete once it contains a root module, and a tree of child modules.
- The root module is the working directory where Terraform is called.

---
