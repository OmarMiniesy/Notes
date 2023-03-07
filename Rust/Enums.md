
### General Notes

> Enums in [[Rust]] are a way of saying that a value could be one of a possible set of values.
> The values inside the enum are called variants
> They can either be assigned their types or not

>Enums can have [[Methods]]

---

### Implementation

```Rust
enum IpAddress {  //name
  V4,   //variants
  V6,  
};

let four = IpAddress::V4;

enum IpAddr {
  V4(u8, u8, u8, u8),
  V6(String),
};

let addr = IpAddr::V4(127, 0, 0, 1);

```

> To create an instance of this enum, use the name of the enum, `::` , and then the variant
> [[Functions]] that take enum parameters dont care which value they are.
> We can add the [[Data Types]] to the variant. This type can be anything, even a struct.

---

### Option Enum

> The `option` type encodes the scenario where a value can be something or it can be nothing.
> Replacement for `NULL` that isnt found in Rust.

```Rust
enum Option<T> {
    None,
    Some(T),
}

//can use the enum, or can use it directly
let x = Some(5); //this makes x of type int.
let some_char = Some('c');
let absent_num: Option<i32> = None;
```
> The `<T>` is a generic type parameter. When the `Some` is used, the `<T>` makes the overall `option<T>` of the type used in `Some`.
> When the value is None, we use the `Option` with a defined data type that will allow the compiler to infer the type.

> We cannot use `<T>` operations on an `Option<T>` variable. It must first be converted, and all cases should be handled.
> The `match` expression helps do that. [[Control Flow]]

---
