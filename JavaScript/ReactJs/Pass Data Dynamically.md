
### General Notes

> To pass data dynamically in [[JavaScript/ReactJs/Components]], we need to pass parameters from the `App.js` to the `component-name.js` files.

---

### Method

> When calling the component, we can add values to be passed on the component
> These values are then stored as key-value pairs in an object. This object is a parameter for the component.
> This object can then be called in the component itself, and its data can be can be accessed

> To use JavaScript code inside the HTML code, we need to use `{}`. 
> Inside them, code is treated as JavaScript.
> Only accepts single line code, and not block statements.

>`App.js`
```JavaScript
//
<Mins text = "mins" <key> = "value"/>
//
```

>`Mins.js`
```JavaScript
function Mins(props) {
  return (
    <div>
      {props.text} {props.<key>}
    </div>
  );
}
```

---
