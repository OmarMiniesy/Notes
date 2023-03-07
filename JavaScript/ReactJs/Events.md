

### General Notes

> To handle events in [[ReactJs]], similar to [[Angular]] [[Event Binding]], we add an attribute for the HTML element that will have this event. Cannot be custom components.
> This attribute is the type of event, and equate it to `{}` that has a JS function that will respond to this event.
> Inside the [[JavaScript/ReactJs/Components]] function
> `event = {<js function>}`

> The `event` attribute is in camel case.
> The js function can be whatever type of function
> The js function is defined **inside** the component function itself, not outside 

---

### Event Props

> For our own components, we cannot use the built in props such as `onClick`.
> We need to define our own props from [[Pass Data Dynamically]], possible name them the same, and use them to complete events.


> Add an `onClick` event listener to a custom component.
1. Add `props` in the function of the component that is being called
2. From where the function is called, add `name = {whatever}`.
3. In the component being called, use `onClick = {props.name};`

> What this does, is that the from where the component is being clicked, it wants to do `whatever`. Once it is clicked, the `onClick` event attribute found in that component is triggered, and it calls on `props.name`. This `name` then maps it to `whatever` to complete the goal.

> We can also change this by instead of making the `onClick` call `props.name`, we can make it call a function inside the same component. The function then calls `props.name`.

---
