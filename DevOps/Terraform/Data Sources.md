### General Notes

These allow [[Terraform]] to include data that is externally defined.
- Whether that be outside of Terraform or another Terraform configuration.

Data sources are used to retrieve and use read-only information that is either computed, existing in the cloud environment, or managed outside of Terraform, without creating or modifying resources.

> [[Provider]]s can offer their own data sources alongside the [[Resources]] that can be used.

Data sources can also utilize the [[Meta-Arguments]] that are available for the [[Resources]], except the `lifecycle` argument. 

---
### Data Blocks

The `data` block instructs Terraform to read information from the given data source, and then export it under a local name.
- This name can only be used inside the same Terraform module.
- The name and data source together uniquely identify the resource block.

```TerraForm
data "<data_source>" "<name>"{
 #argumets
}
```
- The arguments that are defined are unique to the data source chosen.

> Data sources belong to [[Provider]]s, and the arguments inside are unique to that provider. Check the [[Terraform]] registry for the list of providers and the data sources they provide.

To use the data that is read by the data sources:
```terraform
data.<data_source>.<name>.<attribute>
```

---
