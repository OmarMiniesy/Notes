
### General Notes

> A way of dynamically changing HTML properties in the DOM for [[Angular]] [[Components]] 
> Can also use [[String Interpolation]] instead

___

### For HTML Elements

>Since we change the properties of elements of the HTML file, we need to bind this property to something in the typescript file that can change it. However, need to make sure that the types match to achieve proper functionality.


>inside HTML file
```HTML
<button class="btn btn-primary" [disabled]="!allowNewServer" >New Server</button>
```
*  `disabled` is an HTML element property that doesnt allow a button to click
* To change that, we bind `disabled` by adding `[ ]`  and equating it in qoutes to something to make that change dynamically.
* Inside the qoutes is a typescript expression.
* `allowNewServer` is a boolean variable, with different values, the button can become clickable or not.

---

