### General Notes

These are used to denote the beginning or the end of an expression or word.

---
##### Caret `^`

This is used to match strings that start with the given letter or expression.
- Example: Select the string that begins with `x`, `xor` and `or`.
```
/^x/
```

##### Dollar Sign `$`

This is used to match strings that end with the given letter or expression.
- Example: Select the string that ends with `t`, `hat` and `cap`.
```
/t$/
```

##### Word Boundary `\b`

This is used to match letters at the end of a word, that is, followed by a non-word character.
- Example: Given `she sells seashells` string, select the words that have `s` as a word boundary.
```
/s\b/
```
- This here selects `sells` and `seashells`. The first is followed by a space, and the second is followed by a new line.

> The opposite exists for **Not Word Boundary** using `\B`.

---