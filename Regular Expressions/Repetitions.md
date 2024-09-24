### General Notes

To specify that a certain character will be repeated, we can use special characters from `+*?{}` those to do just that.
- They are also called *quantifiers*.
- All the examples here use quantifiers on single characters, but they can be used on anything else, such as [[Groups]] and [[Character Classes]]. This is just for simplicity.

---
##### Asterisk `*`

This special character is used to denote matching 0 or more of that character.
- Example: Match these strings, `b`, `be`, `bee`, `beee`.
```
/be*/
```

##### Plus `+`

This special character is used to denote matching 1 or more of that character.
- Example: Match the first 3 strings, `be`, `bee`, `beee`, `b`.
```
/be+/
```

##### Question Mark `?`

This special character is used to denote an optional character.
- Example: Match these 2 strings, `color` and `colour`.
```
/colou?r/
```

> It also makes any preceding *quantifiers* to be lazy, that is, selecting the least amount of characters possible to match the string. 

##### Curly Braces `{}`

These are used to denote the 
1. Exact number of times
2. range of numbers
3. Or minimum number of times
to repeat a character.

- Example: select the string with only 2 `e`s, `beer`, `beeer`, `beeeer`
```
/be{2}r/
```

- Example: select the string with at least 2 `e`s. This is done by adding a comma `,` in the curly braces after the desired minimum.
```
/be{2,}r/
```

> To specify a range, simply add 2 numbers separated by a comma. `{a,b}`

---