
### General Notes

> Components in [[ReactJs]] are simply functions
> They have their own HTML code

> Components are combined together to build a project
> They introduce modularity

> Components should be placed in `/src/components` folder.
> If the `components` folder doesnt exist, add it. 

> There is the main component, `App.js`
> Keep the `App.js`, `index.css`, and `index.js` outside of that folder

---

### Creating a Component

> Component names must start with capital letters. React differentiates between HTML and custom components by that.
> Create a `.js` file with the name of the component.
> Add this file to the `/components` directory

>Inside the `Mins.js` file
```JavaScript
function Mins(){
	return (
		//HTML CODE 
	);
}

export default Mins;
```

---

### Using this Component

> Go the `.js` file that will have this component 
> Import the component `import <component-name> from './components/<component-name>';`

> To add the component, simply use its name in a self closing tag or a normal tag.

---

### Dynamic Passing of Data to Components

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
