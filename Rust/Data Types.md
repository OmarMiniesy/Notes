
### General Notes

> [[Rust]] is statically typed, meaning that compiler must know types of all variable at compile time.

---

### Scalar Types

> Represents a single value
* Integers
* Floats
* Booleans: `bool`
* Characters: `char`

##### Integers
> Size from 8, 16, 32, 64, 128 bits, or arch
> Can be signed or unsigned
> For signed `i<size>`
> For unsigned `i<size>

> If the sizes become overflowed, the program will panic: exit with an error
> If the `--release` flag is set, the overflow will wrap around.

##### Floats
> `f32` or `f64` 
> Default is `f64`

---

### Compound Types

> Multiple values into one type
* Tuple
* Array

##### Tuple
> Group values of different types together
> They have fixed length
> The values are ordered with their types

> To get the value of a single element in the tuple, use pattern matching to destructure
> Can also access elements directly by using a period `.` followed by the index

``` Rust
let tup: (i32, i16, f64) = (20, 15, 43.2);

let (x, y, z) = tup; //pattern matching and destructuring
println!({x}, {y}, {z});

let x: (bool, char, i32) = (true, 'Z', 25);
let mins = x.0;
let mins1 = x.1;
let mins2 = x.2;
```

##### Array
> Every element in the array is of same type
> Array has fixed length

> Create array by simply listing the elements in square brackets separated by commas
> Create array by adding in the type `[type; size]` and equating to elements in square brackets
> Create array of the same element repeated n times `let a = [<element>; n];`

> Access arrays using indices

``` Rust
let months = ["jan", "feb", "march"];
let nums: [i32; 3] = [1, 2, 3];
let five = [5; 3]; //3 elements in the array all 5

let jan = months[0];
```
---
