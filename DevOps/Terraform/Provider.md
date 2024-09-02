### General Notes

There are plugins that allow [[Terraform]] to interact with providers, such as cloud providers SaaS providers, and other APIs.

These providers allow the configuration to utilize extra [[Resources]] and [[Data Sources]].
- Providers are external from Terraform itself, and they are listed in the [Terraform Registry](https://registry.terraform.io/browse/providers).

> Recommended to constrain the acceptable provider version in the provider block configuration because newer versions that are constantly being released might break the configuration.

---
### Provider Requirements

Before any provider is to be used in a module, it must first be declared in the `required_providers` block.
- This declaration includes the *local name*, the *source location*, and the *version*.
- This local name is the name used everywhere in the [[Terraform]] module.
```terraform
terraform {
  required_providers {
    mycloud = { #local-name
      source  = "mycorp/mycloud"
      version = "~> 1.0"
    }
  }
}
```

> This block **must** be nested in the top level `terraform` block.

---
### Provider Configuration

A provider block needs a name only, and in its body are the arguments that are provider specific.
- It is a standard to use the preferred name that the provider utilizes, or the *local name*, which should be defined in the `required_providers` block.
- The documentation for each provider lists the configuration arguments that it expects.

```TerraForm
provider "<name>" {
 #arguments
}
```

> To use any provider, it must already be declared in the `required_providers` block.

###### `alias`: Multiple Provider Configurations

To define multiple configurations for the same provider, the `alias` [[Meta-Arguments]] can be used.
- To do that, multiple `provider` blocks need to be defined with the *same provider name*.
- Add the `alias` argument with a value.

> Check the `provider` meta-argument in [[Meta-Arguments]].

```Terraform
provider "aws" {
 ...
}

provider "aws" {
 ...
 alias="west"
}
```

To reference the original provider with default configurations, simply call its name `aws`, but to reference the one with different configurations, reference them using the alias: `aws.west`.

###### Default Provider Configurations

To use providers without using the `provider` meta-argument, [[Resources]] with the first name (resource type) matching that of a provider will get the default configurations of that provider. 
- In other words, using the preferred `local_name`. 
- For example, a resource with name `aws_instance` will use the `aws` default configurations.

---
