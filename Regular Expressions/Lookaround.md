### General Notes

Used in [[Regular Expressions]] to look for strings and patterns that are present after or before certain phrases.

If the match we are looking for comes right before or right after another phrase, we can use *lookarounds* to achieve our goal, with 4 different variations:
- Positive lookahead `(?=)`
- Negative lookahead
- Positive lookbehind
- Negative lookbehind

##### Positive lookahead `(?=)`

This matches the string that has the specified phrase placed right after it.
- For example, capturing the number that has the phrase `PM` right after it in `5 AM 3 PM`.
```
/\d(?=PM)/
```

##### Negative lookahead `(?!)`

This matches the string that does not have the specified phrase placed right after it.
- For example, capturing the number that does not have the phrase `PM` right after it in `5 AM 3 PM`.
```
/\d(?!PM)/
```

##### Positive lookbehind `(?<=)`

This matches the string that has the specified phrase placed right before it.
- For example, capturing the number that has the phrase `AM` right before it in `5 AM 3 PM`.
```
/(?<=AM)\d/
```

##### Negative lookbehind `(?<!)`

This matches the string that does not have the specified phrase placed right before it.
- For example, capturing the string that has the number `3` right before it in `5 AM 3 PM`.
```
/(?<!3)\w+/
```

***
