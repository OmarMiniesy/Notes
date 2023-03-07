
### General Notes

> Each value in [[Rust]] has only one owner at a time
> When the owner goes out of scope, the value is dropped.

---

### Scope

> The range within a program for which an item is valid and can be used.
> When a variable is in scope, it is valid until it goes out of scope

> Memory is automatically returned once the variable that owns it is out of scope. Done by `drop`

---

### Cloning or Moving Data on the Heap

> Deep copying is not implemented by rust
> This means that if two variables point to the same data, the second variable is the one kept, and the first is discarded.
> This is called shallow copying, but rust calls it `move`.
> We say a variable has `moved` into another if the second one points to the same thing pointed at by the first.
> To actually copy data, we need to use the `.clone()` function.

---

### Copy and Drop on the Stack

> Variables on the stack arent cloned or moved, they are copied. They have the `copy` trait.
> The `copy` trait means that the variable doesnt move, it gets copied to another location.
> The `copy` trait is added to the basic [[Data Types]].

---

### Ownership in [[Functions]]

> For functions, passing data into functions means that they are no longer in scope to be used after that.
> Returing values can transfer ownership.

---

### References and Mutable References

> Allows us to borrow data without causing to go out of scope, and hence we never transfer ownership.

> A reference is like a pointer in that its an address we can follow to access the data stored at that address.
> References can be used using the `&` operator. Add the `&` while passing the parameter and inside the function header before the variables.
> References solve the issue with functions, where we cant access the data anymore.

> To change the data pointed at by a reference in a function, we need to make sure that the reference is mutable [[Variables and Mutability]].
> Do this by adding `&mut` in both locations: the parameter passing and the function header.

##### NOTE
> Cannot have multiple mutable to the same value, and cannot have mutable and normal reference to the same value.
> Can only have 1 mutable, or multiple nonmutable to the same value.
> Dangle Reference: we create a reference, and then this reference goes out of scope so then we cannot use it.

---
