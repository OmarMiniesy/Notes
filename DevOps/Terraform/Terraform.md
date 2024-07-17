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
