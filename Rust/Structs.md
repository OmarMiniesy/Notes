
### General Notes

> Structs in [[Rust]] hold multiple related values that dont have to be of the same [[Data Types]]
> More flexible than tuples as each piece is named, don't have to rely on order.
> They can have [[Methods]]

---

### Implementation and Usage

> Keyowrd `struct` followed by the name, then curly brackets to hold the fields and their data types.

```Rust
struct User {
  active: bool,
  username: string,
}
```

> To use a struct, we need to create an instance by specifying values for the fields as key-value pairs.
> To get a value from a struct, use the dot notation `.`
> To change a value in the struct, the entire struct must be `mut` mutable.

```Rust
let mut user1 = User{
  active: true,
  username: String::from("minso"),
};

let x = user1.active;
user1.username = String::from("minsy");
```

---

### Creating Structs

##### Field Init Shorthand
> If a function is creating a struct, and the parameters have the same name as the fields, we dont have to write it.
```Rust
fn build_user(username: String) -> User{
  User {
  active: false,
  username,
  }
}
//function creates struct and returns it
```

##### Struct Update
> Create a new instance of a struct that includes most of the values from another instance.
> The old struct will be **NOT** deprecated as the data has been moved only if its fields types can be copied on the stack.  ([[Ownership and References]])
> This occurs because we use `=`, we are moving the data.

>Add `..<struct-name>` at the end to fill any remaining values
```Rust
let user2 = user1 {
active: false,
..user1
}
```

---

### Tuple Structs

> Structs that are similiar to tuples as they don't have names for the fields, only the data types.
> `struct` followed by name followed by data types.
> Instances of different tuple structs can be destructured, and have the individual fields accessed by dot notation.

```Rust
struct Color(i32, i32, i32);
let red = Color(255, 0, 0);
println!("{}, {}, {}", red.0, red.1, red.2);
```

---

### Unit-Like Structs

> Structs that dont have any fields.
> Implement a trait on some type but no data to be stored on the type itself.
```Rust
struct mins;
let x = mins;
```

---

### Printing Structs

> To print structs, the normal `println!()` function wont work as it only works with primitive data types.
> Replace the `{}` with `{:?}` or `:#?`
> To use this, we must add `#[derive(Debug)]` to the struct

```Rust
#[derive(Debug)]
struct Rectangle {
    width: u32,
    height: u32,
}
fn main() {
    let rect1 = Rectangle {
        width: 30,
        height: 50,
    };
    println!("rect1 is {:?}", rect1);
}

```

---
