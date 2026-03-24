### General Notes

This is a JSON CLI parser tool.
- [JQ Manual](https://jqlang.org/manual/)

---
### Using JQ

To remove the square brackets, that is, to remove the array indexing on the JSON file:
```
jq '.[]'
```
- Use this as the first sub command before piping into another command when needed.

To obtain the value of a certain key, can use the dot operator to look for it:
```
jq '.key1.key2.neededKey'
```

To return each JSON object on its own in 1 line to help with grepping for whole events, we can use the `-c` flag.
```
jq '.[]' -c
```

To select when a key is equal to a certain value, we can use this:
```
jq '.[] | select(.key == value)'
```

---