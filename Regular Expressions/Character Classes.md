### General Notes

This syntax is used in [[Regular Expressions]] to ease the process of matching, by specifying alternatives in the forms of sets.
- Moreover, it provides certain special characters that can match entire character types for simplicity.

---
##### Character Set `[ABC]`

This expression can be used to match a character for each character in the set.
- Example: given the 2 strings `bad` and `bed`, find a regex that matches both.
```
/b[ae]d/
```
- The `b` and the `d` are constant, but the letter in the middle, is not, so we specify a character set where the character in the middle can be any of the ones in that set.

##### Negated Character Set `[^ABC]`

This expression can be used to match with the words that do not have the characters specified inside the set.
- Example: given the 3 strings `bad`, `bed`, and `bud`, find a regex that matches only the first two.
```
/b[^u]d/
```
- Same as above, but this time, it will match all the words that start with a `b`, do not have a `u` in the middle, and then have a `d` at the end.

##### Letter Range `[a-z]`

This expression can be used to find all the letters in the specified range. 
1. It *case sensitive*.
2. It is inclusive, the boundaries of the limit are also matched.

- Example, given the string `abcdefgh`, match only the letters from `d` to `g`.
```
/[d-g]/
```

The letter range syntax consists of only 3 elements, the start, the `-` and the end, therefore, we can have more than one character range in the same `[]` brackets.
```
/[a-cA-C]/
```
- This range matches anything from `abc` and `ABC`.

> The same exists for numbers, using a **Number Range**, as well as the **Negated** version `[^d-g]` of each.

##### Word `\w`, Digit `\d`, Whitespace `\s`

- Using the `\w` matches any *alphanumeric character*.
- Using the `\d` matches any digit.
- Using the `\s` matches any spaces, tabs, and line breaks.

Combining these with the *quantifiers* in [[Repetitions]] works, as well as placing them inside expressions behind certain characters or after them to select patterns.

> There also exists the not word `\W`, the not digit `\D`, and the not space `\S`.

---
