### General Notes

A regular expression, commonly referred to as *regex*, is a sequence of characters and symbols combined to match and find specific patterns inside text.

The way regex works is by specifying characters, and these characters are then matched against the input string.
- These can be normal characters, such as letters from the alphabets, or numbers.
- They can also be special characters, such as `/\^+*[]()?=!$.` to specify more complex matches.
###### Basic Syntax

A regular expression can be created by using a regex literal, which consists of a pattern that is enclosed between two forward slashes `/`.
```regex
/ab+\w/g
```
- The pattern here is `ab+\w`, and it is enclosed by the 2 forward slashes.
- The final character after the closing forward slash, the `g` is a flag.

> After the closing forward slash, there can be flags that change how the expression is interpreted. 

---
### Flags

These are also called *modifiers*, and they change how the expression is evaluated.
- They are placed right after the closing forward slash.
##### Global Flag `g`

This flag causes the expression to select **all** the matches from the input text.
##### Multiline Flag `m`

Regex normally sees all the input text as one line, but the multiline flag allows handling each line separately.
##### Case-insensitive Flag `i`

This causes the regex to handle the expression regardless of case.

---