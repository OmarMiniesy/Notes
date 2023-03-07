
### Mutability

 > Variables in [[Rust]] are immutable, meaning their values cannot be changed
 > Variables must be mutable to be change by adding `mut` keyword
 > Cannot play with two variables of different [[Data Types]] in the same expression or statement.
 
```Rust
fn main() {
	let mut x = 5;
	x = 6;
}
```

---

### Constants

> Constants are values that are bound to a name and cannot change
> Cannot use `mut` with constants
> Declate constants using the `const` keyword instead of `let`
> Constants can be declared in the global scope
> By convention, their names should be all caps and spaces should be underscores.

```Rust
const MINS_IS_RUST: u32 = 50;
```

---
