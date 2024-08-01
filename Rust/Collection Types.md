
### General Notes

> [[Rust]] library offers useful data structures called collections.
> They contain multiple values, and their data is stored on the heap.
> Data size doesn't need to be known at compile time, and can have its size change dynamically while running

---

### Vector

> Store a number of values of the same [[Data Types]] next to each other.
> Useful for storing a list of items.

##### Creation
>To create a vector, use the `Vec::new()` function. 
>Can add the type annotation if it will be empty on initialization.
>If we give values, Rust infers the data type.
```Rust
let v: Vec<i32> = Vec::new();

let v = vec![1, 2, 3];
```

##### Update
> To update a vector, it must be mutable `mut`, and we can use the `push` method.
> We don't need to identify type as Rust infers the type from the data we push
```Rust
let mut v = Vec::new();
v.push(1);
v.push(2);
```

##### Reading
> Can read the values in a vector through referencing [[Ownership and References]]
> We can use indexing or use the `get` method.
> Using the `get` method returns `Option<&T>`, so we can use with `match` [[Control Flow]]
```Rust
let v = vec![1, 2, 3, 4];

let one = &v[1];
let two: &i32 = &v[2];  //added the type to know that we must reference.

let third:Option<&i32> = v.get(2);  //can use with match as it returns option<&T>
```

##### Important Note: Mutability and Immutablity in Vectors
> If we make the vector mutable but take a reference of one of its element and make it immutable, we cannot change the mutable vector since now we have 2 references of different types to the same element in the same scope. [[Ownership and References]]

##### Iteration
> using for loop [[Control Flow]]
> Can get either immutable or mutable references.
> Can't insert or remove values from a vector as the for loop holds the reference to it at that time.
```Rust
v = vec![100, 200, 300, 3];
for i in &v {
  println!("{i}");
}

let mut v = vec![100, 200, 300, 3];
for i in &mutv{
  *i += 50;
}
```
> Use the `*` operator to dereference the reference `&` operator

---

### Hash Maps

> `HashMap<K, V>` stores a mapping of keys K to values V using a hashing function.
> Stores data on the heap, all keys have the same type, and all values have the same type.
```Rust
use std::collections:HashMap;

let mut scores = HashMap::new();
scores.insert(String::from("Blue"), 10);
scores.insert(String::from("Yellow"), 20);

let team_name = String::from("Yellow");
let score = scores.get(&team_name).copied().unwrap_or(0);
//copied because it handles the option<T> returned by .get()
//unwrap_or(0) sets the result to 0 if the key isnt found.

for (key, value) in &scores
{ println!("{key}: {value}"); }
```

> We can override the value present if we enter the same key

> `entry` function
---
