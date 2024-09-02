### General Notes

These are keywords used in [[Terraform]] to control how [[Resources]] are created, updated, and destroyed.
- Used to manage the dependencies between resources as well.

---
### `depends_on`

Used to handle the dependencies that some [[Resources]] require when [[Terraform]] *cannot automatically infer* the needed version.
- Versions need to be explicitly defined when a resource relies on another resource's behavior but it doesn't access any of its data.

> This meta argument must be used as a last resort since it changes the order in which Terraform executes it plans.

Instead of this meta-argument, **expression references** can be used to help terraform with the dependencies.

Usage:
```TerraForm
resource "type" "name" {
 depends_on = [
  <type>.<name>
 ]
}
```

---
### `count`

To manage several similar objects without writing the code for each object, the `count` meta-argument can be used.
- If a module includes the `count` argument with an integer number, then that number of instances of the object will be created, destroyed, updated, etc..
- It can also be assigned value from numeric **expressions**, however, the value must be known before any actions are taken by Terraform.

> Each instance has its own distinct infrastructure object associated with it.

For blocks that have the `count` argument, there is an attribute that is accessible by each instance created.
- This attribute is `count.index`, and it allows modification of specific instances.
- Each instance can be accessed using the following syntax: `module.name[index]`.

Usage:
```TerraForm
resource "type" "name" {
 count = 5
}
```

---
### `for_each`

Used to manage several objects by taking as input a map or a set of strings for the required values.
- An instance is created for each member of the map or value in the set of strings.

> Similar to the `count` argument, however, it is preferred when the arguments need distinct values that cannot be inferred from an integer number.

Working with a `set`:
```TerraForm
resource "type" "name" {
 for_each=toset(["a","b","c"])
 letter=each.key
}
```
- To access an element of the set use `each.key` or `each.value`.

Working with a `map`:
```TerraForm
resource "type" "name"{
 for_each=tomap({
  a="east"
  b="west"
 })

name=each.key
location=each.value
}
```
- To access the elements of a map, use `each.key` for the keys of the map, and `each.value` for the values of the map.

> Check the [documentation](https://developer.hashicorp.com/terraform/language/meta-arguments/for_each) for how to use `for_each` between multiple resource blocks, and how to chain it.

---
### `provider`

Specify which [[Provider]] configuration to use.
- We can use multiple different configurations of the same provider by using the `alias` attribute, if the default one is needed, then there is no need for it.
- The new provider block with the alias can then be called using the `provider` argument.

To use the `provider` argument, specify the provider name followed by the alias: `provider.alias`.
- If there is no alias, then simply omit it.

```Terraform
provider "google"{
 alias="europe"
 region="europe-west1"
}

resource "google_test" "example" {
 provider=google.europe
}
```

> Resource type names are interpreted by default by Terraform, and the first word is the name of the provider, in this case, `google`. Since there is a `provider` argument, then the default configurations are ignored, and the ones chosen are applied.

---
