
### General Notes

The language is used to create the configuration files that describe the needed *resources* that will be instantiated.
- These resources are basically the infrastructural needs.

This language is a **declarative** language, where the end goal is described, but not the process required to reach it.

> [Styling Guide](https://developer.hashicorp.com/terraform/language/style).

---
### Blocks

The files are mainly comprised of these *blocks* of code, which is the main syntax of the language.
- These blocks represent the configuration of a component, like [[Resources]].

``` terraform
<BLOCK TYPE> "<BLOCK LABEL>" "<BLOCK LABEL>" {
  # Block body
  <IDENTIFIER> = <EXPRESSION> # Argument
}
```

- The `block type` is basically the component that has its configuration or details described.
- The `body` of the block contains the configuration information, and can contain other blocks as well.
- There can be 0 or more `labels` for a block, which can be used to identify the block differently based on the block type.
- The configuration contains *arguments*, which are used to assign values to names, sort of like giving values to variables.

---

