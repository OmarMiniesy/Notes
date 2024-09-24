### General Notes

The basic syntax of [[Regular Expressions]], matching letters, numbers, and special characters.

---
##### Letters

To match letters against letters, we can use the actual letters in the regex.
- Example: given `abc123`, `abf156`, find a regex that matches both.
```
/a/
```
- The answer would simply be the letter `a`, as it is present in both strings.
- We can also use `\ab\`, as the same pattern is present in both strings.

> The order inside the regex matters, so in the case of `/ab/`, the pattern will need the `a` to come first, then the `b`.

##### Numbers

The same goes with numbers, we can use the actual number in the regex.
- Example: given `abc123`, `abf156`, find a regex that matches both.
```
/1/
```
- The answer would simply be the letter `1`, as it is present in both strings.

##### Wildcard Operator: `.`

To match against any character, we can use the dot `.`.
- It matches letters, numbers, special characters, and spaces, **but not new lines**.
- If the full-stop, or period character, is needed, we can escape the operator using the `\`, so the expression would become `\.`.

##### Break Out of Special Characters

To match one of the special characters used by regex, such as `.*+` and so on, we can break of out it using the backslash `\`.
- So to match with a `+`, we can write `\+`.

---
