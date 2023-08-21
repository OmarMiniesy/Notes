
### General Notes

> Components in [[ReactJs]] are simply functions.
> Similar to [[JavaScript/Angular/Components]].
> They have their own HTML code.

> Components are combined together to build a project.
> They introduce modularity.

> Components should be placed in `/src/components` folder.
> If the `components` folder doesnt exist, add it. 

> There is the main component, `App.js`.
> Keep the `App.js`, `index.css`, and `index.js` outside of that folder.

---

### Creating a Component

> Component names must start with capital letters. React differentiates between HTML and custom components by that.
> Create a `.js` file with the name of the component, first letter of name should be capitalized.
> Add this file to the `/components` directory.

>Inside the `Mins.js` file.
```JavaScript
function Mins(){
	return (
		//HTML CODE 
	);
}

export default Mins;
```
> The name of the function should be capitalized.

---

### Using this Component

> Go the `.js` file that will have this component.
> Import the component into the required file that will use it. 
``` javaScript
import <component-name> from './components/<component-name>';
```
> The file after the `from` should be the path to the component, and omit the `.js` extension.

> To add the component, simply use its name in a self closing tag or a normal tag.

---