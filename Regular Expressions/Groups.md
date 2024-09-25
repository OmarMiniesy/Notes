### General Notes

Sometimes, we need to simplify matters in [[Regular Expressions]] by creating groups to hold information in a single unit, similar to mathematics.

We can group some expressions, and then use these groups as references, or to extract information.
- This is done using the parenthesis `()`.

---
##### Capture Group `()`

To create a group, we simply surround the expression we want with brackets.
```
/(ha)/
```
- This selects and extracts the first `ha` from the input string.

##### Referencing a Group `\num`

To reference that group again, that is, to match the results of that capture group and use them again, we use `\` followed by the number of that group, starting from 1.
- Example: Given the strings `hah`, `dad`, and `bad`. Write a regex that captures only the first 2.
```
/(\w)a\1/
```
- We can use a group since the first letter of the first 2 words is the same as the last letter. Therefore, if we place the first letter in a group, and then reference it, we can complete the task.
- We use the `\w` to denote a single character inside the group, and then call that group again, with its value of that captured single character using `\1`.

##### Non-Capturing Groups

These are groups that will not be referenced. They follow the same syntax of the parenthesis, but include `?:` in the beginning.
```
/(?:ha)/
```

##### Alteration `|`

This is used to specify that an expression can be in different expressions. It is similar to the [[Character Classes#Character Set `[ABC]`]], but it operates on the expression level not the character level.
- Example, select both of these words, `cat` and `rat`.
```
/(c|r)at/
```

> Alterations can also be used outside of groups.

---
