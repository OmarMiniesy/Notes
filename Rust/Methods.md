
### General Notes

> Methods in [[Rust]] are similar to [[Functions]]
> They are different only in that they are declared within the context of a [[Structs]], or [[Enums]], or trait object.

---

### Implementation

> First parameter is always `self`, it represents the instance of the struct that the method is being called on. 
> The method is added in the  `impl <structname>` block.
> We can define multiple methods inside the `impl` block. They all apply to that struct.

> Instead of using `self: &self`, we can simply use `&self`.
> If the method is going to change the instance itself, we should use `&mut self`. [[Data Types]]
> This is only for the first parameter, the rest follow normally,
> Change the instance to `self` in the function

> We can then call this method using the dot operator.

```Rust
#[derive(Debug)]
struct Rectangle {
    width: u32,
    height: u32,
}

impl Rectangle {
    fn area(&self) -> u32 {
        self.width * self.height
    }
}

fn main() {
    let rect1 = Rectangle {
        width: 30,
        height: 50,
    };

    println!(
        "The area of the rectangle is {} square pixels.",
        rect1.area()
    );
}

```

---

