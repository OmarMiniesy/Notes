
### Main Function

> The entry point of the [[Rust]] program

---

### Defining Functions

> Define functions using the `fn` keyword
> Can be defined anywhere in relation to the main function as long as they are in an accessible scope

---

### Parameters

> variables part of the function signature
> The variable type is specified in the function signature

``` Rust
fn main() {
    print_labeled_measurement(5, 'h');
}

fn print_labeled_measurement(value: i32, unit_label: char) {
    println!("The measurement is: {value}{unit_label}");
}
```

---

### Statements and Expressions

>**Statements** are instructions that perform some action and do not return a value.
  **Expressions** evaluate to a resultant value. Do not end in semicolons

> Cannot assign statements to statements, but can assign statements to expressions.

``` Rust 
fn main() {
    let y = {
        let x = 3;
        x + 1 //no semicolon, if there is, it will be a statement and wont work
    };

    println!("The value of y is: {y}");
}

```
> No ending semicolons in the expression

---

### Return Values

> Declare the type of return values after `->` at the end of a function signature
> Rust returns the value of the final expression in the function.
> Can return early by using the `return` keyword

```Rust
fn main() {
    let x = plus_one(5);

    println!("The value of x is: {x}");
}

fn plus_one(x: i32) -> i32 {
    x + 1
}

```

---
