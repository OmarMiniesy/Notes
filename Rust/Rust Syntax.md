
> Syntax for [[Rust]]
---

### General Notes

> Statically and strongly typed language meaning variable types cannot changed
> Same as [[TypeScript]]

---

### Variables 

```Rust
fn main(){
	let x = 4;
	x = 3; // error
	let x = 4; // redeclaration (overriding)
	
	let mut y = 5;
	y = 6;
}
```
> Variables defined through `let` are immutable, they cant be changed except by redeclaring the variable.
> Redeclaration can also change the type of the variable. This only works if `mut` is not added to the variable
> Fixed by adding  `mut` 

---

### Constants

> Immutable variable, type and value cannot change
> Convention is name is all caps and spaces are underscores
> Type must be defined, and value must be assigned

``` Rust 
const SECONDS_IN_MINUTE: u32 = 60;
```

---

### Scope (Name Shadowing)

``` Rust 
fn main(){
	let x = 4;
	x = 3; // error
	let x = 4; // redeclaration (overriding)
	{
		// inside a different scope
		//outside variables can be used inside here
		// variables inside here cannot change the things outside
	}
	let mut y = 5;
	y = 6;
}

```

---
