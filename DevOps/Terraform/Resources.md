### General Notes

This is the smallest *infrastructure* object that [[Terraform]] defines.
- Defined using `Blocks` using the [[Configuration Language]].

Each resource that is created is specified using the resource type, and for each type, there is different configuration that is specified using its arguments.
- Some resources are made available through [[Providers]].

For the resources defined in the configuration files to be deployed as real infrastructure, the `apply` process must be done.
- When an infrastructure object is created, it is saved in the *state*.
- When new resources are added, or old resources are modified, Terraform updates the state with the new configurations.

Some resources need to be used in relationship with other resources, meaning that they need to be processed before other resources are processed.
- This is called a dependency, and these are handled automatically by Terraform.

> Full documentation [here](https://developer.hashicorp.com/terraform/language/resources).

---
### Resource Blocks

This defines the basic syntax of `resources`.
- It contains a *resource type*, a *resource name*, and the *configuration arguments*.

```terraform
resource "resource-type" "resource-name"{
	name=value  # attribute
}
```

###### Accessing Attributes

To access an attribute found in a resource to help configuring another resource, the following syntax can be used `resouce_type.resource_name.attribute`.

---
### Removing and Destroying Resources

To remove resources from the Terraform configuration, simply delete it from the files, this means that the actual infrastructure that was created due to this configuration will be destroyed.

> To remove a resource from the terraform configuration without destroying it, the `removed` block can be used with the `destroy` argument in child `lifecycle` block.

```terraform
removed {
	from = <resource-name>
	lifecycle {
		destroy = false
	}
}
```

---
### Conditionals

To add conditional blocks that are executed depending on the state and how the resource operates, the `postcondition` and `precondition` blocks can be used.

---
