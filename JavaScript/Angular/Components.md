
### General Notes

> A component is a typescript class so that [[angular]] can instantiate to create objects
> Each componenet has its own template, styling, and business logic
> Split a complex application by splitting into multiple components to be reusable

> Application is built by combining multiple components
> There is a root component, `app componenet` where other components are built on top of

---

### Creating a Component

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
	* The HTML template code of that component. Should be referenced using `./` for relative pathing
```JavaScript
import { Component} from '@angular/core'

@Component({
	selector: 'app-server',
	templateURL: './server.component.html'
})
export class ServerComponent {}
```
> Inside `server.component.ts`

```HTML
<h3> Inside the Server Component.</h3>
```
>Inside `server.component.html`

6. 