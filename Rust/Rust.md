
### General Notes

> Programming language interested in low level details
> Expression based language
> Statically typed language
> [The Rust Book](https://doc.rust-lang.org/book/) for documentation and installation
> Rust files end in `.rs` extension

---

### Running a Rust File

1. Save the `.rs` file
2. Navigate to the directory and compile the rust file
```bash
rustc <filename>.rs
```
3. Execute the resulting file
```bash
./<filename>
```

---

### Important Notes

> `main()` function is the first code that runs in every executable rust program
> It can have parameters and can return a value

1. To indent in Rust, use 4 spaces and not TAB
2. Adding the `!` calls a macro and not a normal function
3. Lines should end with `;`

> `hello_world.rs`
```Rust
fn main(){
    println!("Hello, World");
}
```

> Comments are done using  `//` 

---

