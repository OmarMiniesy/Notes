
### General Notes

> A way of reacting to HTML events in the DOM for [[Angular]] [[JavaScript/Angular/Components]] 

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

### Passing and Using Data

> `$event` is a reserved variable name used in the template for event binding
> it is the data emitted by the event between the qoutes

#### A Way to Show User Input As Dynamic Text Changing with Entry

>in HTML file
```HTML
<input type="text" (input)="onUpdateServerName($event)" />
<p> {{ servername }} </p>
```
* Here, the event is input, and the function called in the qoutes gets passed the data being inputted by the event in the `$event` variable
* The `servername` variable should change with keyboard input

>in typescript file
```typescript
servername: string = "empty";

onUpdateServerName(event: Event) {
   this.serverName = (<HTMLInputElement>event.target).value;
}
```
* the parameter is called `event` of type `Event`
* the `event.target.value` is a way of capturing the data from the `Event` variable
* To let [[TypeScript]] know that it is of type `event`, we need to cast it using the `<HTMLInputElement>`

---

