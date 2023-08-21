
### General Notes

> Styling and using `CSS` classes for [[ReactJs]] is different.
> Using the `class` attribute is not supported, but instead, it is called `className`.

> Styling for [[JavaScript/ReactJs/Components|Components]].

---

### Creating Styles

> To create unique styles for different [[JavaScript/ReactJs/Components|Components]] using `className`, we need to create a new file for that componenet.

```
Component.module.css
```

> This should be the name of the `.css` file used for styles for that component.
> Inside it, we can create our own unique styles for that component.

```css
.post{
	background-color:red;
}
```
> This here is a style for the class `post`.
##### Importing and Using the styles

> To import the styles, we need to follow this syntax:

```JSX
import classes from './Component.module.css'

function Component() {
  return (
    <div className={classes.post}>
      <h1>Post</h1>
    </div>
  );
}
```
> Now we can use the `className` attribute with the class name we created to use its styles.
> We do that by referencing the object `classes` and then using the value `.post` from the css file.

---
