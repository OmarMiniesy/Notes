
### General Notes

> A method to bind data in [[Angular]] between the typescript code and template files for [[Components]]
> It works only for anything that can resolve into a string, such as a property, a method, a variable, ...
> Can't write multi-line expressions. Ternary expressions work

---

### Usage

>Inside typescript file
```JavaScript
import { Component } from '@angular/core';
@Component({
  selector: 'app-server',
  templateUrl: './server.component.html',
  styleUrls: ['./server.component.css']
})

export class ServerComponent { 
	serverId: number = 10;
	getServerId (){
		return this.serverId;
	}
}
```


>Inside the template, HTML file
```HTML
<p>Server ID: {{ serverId }}</p>
<p>Server ID: {{ getServerID() }}</p>
```
* Anything inside the `{{ }}` is what is called from the typescript file and resolved to a string 

---
