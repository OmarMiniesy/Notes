
### General Notes

> A way of reacting to HTML events in the DOM for [[Angular]] [[Components]] 

---

### For HTML Elements

> Different to [[Property Binding]] where we use `[ ]`, here we use `( )`.
> Inside the brackets we put the event without `on` and equate it to typescript code in qoutations.


>Inside the typescript file of the component added this method and variable
```JavaScript
  serverCreation = 'No server was created!';
  onCreateServer() {  //put the On here for convention 
    this.serverCreation = 'Server was created!';
  }
```

> Inside the HTML template file
```HTML
<button (click)="onCreateServer()"> New Server </button>
<p> {{serverCreation}} </p>
```

> What happens is that the `serverCreation` variable displayed using [[String Interpolation]] can be changed through clicking the button.
> The button triggers an event `click` which calls the typescript function `onCreateServer` to change the variable.

---

### Passing Input Data

