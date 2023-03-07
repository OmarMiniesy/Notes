
### General Notes

> Conditionals and loops for [[Rust]]
> The match construct.

---

### If Expressions

> Branch depending on condition
> No brackets around the condition
> Will not convert non-boolean types to boolean values

``` Rust
fn main() {
    let number = 6;

    if number % 4 == 0 {
        println!("number is divisible by 4");
    } else if number % 3 == 0 {
        println!("number is divisible by 3");
    } else if number % 2 == 0 {
        println!("number is divisible by 2");
    } else {
        println!("number is not divisible by 4, 3, or 2");
    }
}
```

##### If in a let Statement

> An expression in the curly brackets
> The expressions must be of the same type
``` Rust
fn main() {
    let condition = true;
    let number = if condition { 5 } else { 6 };

    println!("The value of number is: {number}");
}
```

---

### Loops

> Repetittion of block of code
* `loop`
* `while`
* `for`

> `break` keyword to stop loop and jump to code after loop
> `continue` keyword to skip this iteration and go to next iteration
> For loops within loops, these keywords apply to the innermost loop or by using a loop label with the kewyord

---

### `loop`
> Repeat a block of code infinitely or until i tell it to stop explicitly `ctrl + c`
```Rust
loop {
	println!("mins");
}
```
> used to test if something is going to fail

##### Returning values
> Pass the result of an operation out of the loop and into the rest of the code
> Use the `break` keyword and add the value after it

``` Rust
fn main() {
    let mut counter = 0;

    let result = loop {
        counter += 1;

        if counter == 10 {
            break counter * 2;
        }
    };

    println!("The result is {result}");
}

```

##### Loop Labels
> Add `'<loop-label>: loop {}` before loop
> Then, to use this loop label to continue or break from anywhere `break '<loop-label>`

---

### `while`

> To evaluate condition within loop
> Can be achieved using `loop` and a lot of `if-else` statements.
``` Rust
fn main() {
    let mut number = 3;

    while number != 0 {
        println!("{number}!");

        number -= 1;
    }

    println!("LIFTOFF!!!");
}
```

---

### `for`

> To loop a set number of times
```Rust
fn main() {
    for number in (1..4).rev() { //range and reverse it
        println!("{number}!");
    }
    println!("LIFTOFF!!!");
}
```

> To execute code for each item in a collection
``` Rust
fn main() {
    let a = [10, 20, 30, 40, 50];

    for element in a {
        println!("the value is: {element}");
    }
}
```

---

### Match 

> Compare values against patterns and operate based on which pattern matches.
> The expression of the match can be of any type, not just boolean like if statements.
> Then, there arms that contain the pattern and the respective code to be executed.
> Match must be exhaustive: must cover all cases.

```Rust
enum Coin {
    Penny,
    Nickel,
    Dime,
    Quarter,
}

fn value_in_cents(coin: Coin) -> u8 {
    match coin {
        Coin::Penny => 1,
        Coin::Nickel => 5,
        Coin::Dime => 10,
        Coin::Quarter => 25,
    }
}
```
>The [[Enums]] says that the coin can be any one of the 4. The match then takes a variable of the type of the enum and then checks which variant it is.

>To check on `Option<T>` data types for the enum, we check if it is `none` or if it is `Some()`
```Rust
fn main() {
    fn plus_one(x: Option<i32>) -> Option<i32> {
        match x {
            None => None,
            Some(i) => Some(i + 1),
        }
    }

    let five = Some(5);
    let six = plus_one(five);
    let none = plus_one(None);
}

``` 

> There is also  `other` , which is like a defualt that catches the cases that dont match. Use other on the left part of the arm.
> There is the `_` placeholder, which means we dont want to use the value entered. Rust ignores it.
> We can combine `_ => ()` which means if it isnt any of the other cases, then do nothing and ignore it.

---
