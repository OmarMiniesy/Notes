
### General Notes

> A component is a typescript class so that [[angular]] can instantiate to create objects
> Each componenet has its own template, styling, and business logic
> Split a complex application by splitting into multiple components to be reusable

> Application is built by combining multiple components
> There is a root component, `app componenet` where other components are built on top of

> Components are identified by selectors. These selectors can be used as many times as needed.

---

### Creating a Component Manually

1. Create a folder with the same name as the component in the `app` folder 
2. Create a file `<component_name>.componenet.ts` in that folder for the component
3. Create a file `<component_name>.component.html` in that folder for the HTMl template of the component

4. Create the component class and add the component decorator. To add the decorator it must be first imported.
	* Class name by convention. Component name and 'component'
```JavaScript 
import { Component} from '@angular/core'

@Component() //decorator
export class ServerComponent {}
```
> Inside `server.component.ts`

5. Add the metadata for that component in the decorator
	* The HTML tag selector that will be used to call this component. Name by convention 'app' and component name
	* The HTML template code of that component. Should be referenced using `./` for relative pathing.
	* The CSS styling code of that component.
```JavaScript
import { Component} from '@angular/core'

@Component({
	selector: 'app-server',
	templateURL: './server.component.html',
	stylesURL: ['./server.component.css']
})
export class ServerComponent {}
```
> Inside `server.component.ts`

```HTML
<h3> Inside the Server Component.</h3>
```
>Inside `server.component.html`

6. Go to the `app.module.ts` file, the main file for the app and inculde the `ServerComponent`
	* The import statement to include the ServerComponent
	* The name of the component in the declarations part of the decorator
```JavaScript
import { NgModule } from '@angular/core';
import { BrowserModule } from '@angular/platform-browser';

import { AppComponent } from './app.component';
import { ServerComponent } from './server/server.component'; //added this

@NgModule({
  declarations: [AppComponent, ServerComponent],  //added the ServerComponent
  imports: [BrowserModule],
  providers: [],
  bootstrap: [AppComponent],
})

export class AppModule {}
```
> Inside  `app.module.ts`

7. Add the HTML selector of the ServerComponent to the AppComponent HTML file to be able to see the ServerComponent on the main app. 
```HTML
<app-server></app-server>
```
>Inside `app.component.html`

----

### Creating a Component Using the CLI

>Open a terminal window and enter the command to Generate a new Component 
```bash
ng g c servers
```

> A new folder with the component name will be created containing all the necessary files
> The component will be added to the `app.module.ts` file to be used by the app
> The HTML selector of that component can then be used anywhere

---

### Important Notes

> The `templateUrl` or `template`  part of the decorator must be present in the typescript file of the component.
> The `stylesURL` or `styles` part of the decorator is an array.

> Adding in the template or styles part can be inline, meaning that the html or css code can be present in the typescript file itself if its small instead of adding a new file.

> Selectors can be different than being a separate element. Can be `.app-server` so now to add it in the HTML file it should be the class of an already existing element.

---


