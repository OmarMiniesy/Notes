
### General Notes

> Gives more functionality to [[ReactJs]] by allowing [[components]] to register different states
> These states allow us to render different outputs, and to react differently to different cases.
> Useful for interaction with [[Events]]

---
### Implementation

> Must include it in the component file itself
> Inside the component function, add  `useState();` a react **hook**.
> Can give arguments inside this function. `false, true`. The argument given is the initial value.

> `useState()` always returns an array with 2 elements.
> The first is the value of the state itself, `true, false`.
> The second is the function that is used to change the state.

> This can then be used in JSX to play with components.
> Can use the ternary expression.
> Can use `&&`.

```JavaScript
import {useState} from `react`;

function mins(props){
	const [isOpen, setIsOpen] = useState(false);

	{isOpen && <other_component />}; //if isOpen is true, it shows the other component
	{isOpen ? <other_component ? null};
}
```

---
