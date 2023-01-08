
___

### Variables


#### Initialization
``` typescript
let var: number = 20;
let var1 = 20;
const x: string = "mins"
```
> variable called `var` of type `number` with value `20`
> Don't need to add type of variable in TypeScript, it knows automatically


#### Arrays
```TypeScript
let numbers: number[]; //empty array of type number
let numbers: number[] = [1, 2, 3, 4];
let numbers = [1, 2, 3]; //TypeScript knows that it is of type number because all are numbers

// Arrays of type Any can hold different types, not good to use
let numbers = []   //type any
numbers[0] = 1;
numbers[1] = '1'
```


#### Tuples
```TypeScript
let user: [number, string] = [1, "mins"];

user.<any_array_function>
user.push(<xxx>) // can cause errors as it adds a new element with its type, avoid.

user[0].<any_number_function>
user[1].<any_string_function>
```
> Like a key value pair, can have more than 2 elements but use 2 as standard.
> Represented as simple array using JavaScript


#### Enum
```TypeScript
enum Size {Small, Medium, Large}; //small = 0, medium = 1, ...
enum Size {Small = 2, Medium, Large}; //small =2, medium = 3, ...
const enum Size {Small = 's', Medium = 'm', Large = 'l'}; //using const makes javascript output files smaller

let mySize: Size = Size.Medium;
```


#### Functions
```TypeScript
function calculateMins(mins: string) : void{}
//function of return type void with parameter mins of type string.

function calculateMinsPar(num: number, year: 2025) : number{
 return 2 * num * year;
}
calculateMinsPar("omar", 2022);
calculateMinsPar("omar") //year parameter is default to 2025 if no param is inserted for it.

function optionalparam(num: number, num1?: number) : void{} //optional parameter, if not put is undefined.
```
>To check if there will be unused parameters, go to [[TypeScript]] configuration file and uncomment the option `"noUnusedParameters"`
>To check for no implicit returns, or functions that have no return due to logical error, go to [[TypeScript]] configuration file and uncomment the option `"noImplicitReturns"`
>To check for unused local variables in functions, go to configuration file and uncomment the option `"NoUnusedLocals"`
>Functions must be called with exactly same num of parameters with exactly same type.


#### Objects
```TypeScript
let employee: {
	readonly id: number,
	name?: string,
	retire: (age: number) => void  //function that is a property of the employee object
} = {id: 1,
	name: "Mins",
	retire: (age:number) => {  //function definition
	console.log(age)
	}
};

employee.id = 4;   //ERROR, ID is read only attribute and cannot be changed
employee.name = "Omar"
```

___

### Types


#### Any
```TypeScript
let var1;
let var: any;
```
> If no type and no value are added, it is of type any
> Using `any` type without explicitly typing `:any` to a variable causes error, to avoid that change the  [[TypeScript]] configuration file option `"noImplicitAny"` from true to false.


#### Type Alias
```TypeScript
type Employee = {
	readonly id: number,
	name?: string,
	retire: (age: number) => void
}

let emp : Employee = {
	id: 1,
	name: "Mins",
	retire: (age:number) => {
		console.log(age)
	}
}
```
> Create a custom type to be used to create objects without repeatedly creating the object and defining the properties.


#### Union Type
```TypeScript
function mins(omar: number | string): number {
	if (typeof omar === number)
		return omar * 10;
	else
		return parseInt(omar) * 10;
}
```
> Multiple types, to perform actions for a specific type, must put in if statment (Narrowing)
> If not, then only the functions that are common between both data types will be available to use.


#### Intersection Type
```TypeScript

type mins1 = {
	mins1func : () => void
}

type mins2 = {
	mins2func : () => void
}

type mins = mins1 & mins2;

let minsVar: mins = {
	mins1func: () => void,
	mins2func: () => void
}
```
> Type that is equivalent to two types together. 
> When initializing variable of the intersected type, it must initialize all the properties of both types that were intersected.


#### Literal Types
```TypeScript
type metric = 'cm' | 'inch'
let measure : metric; //can only be = 'cm' or 'inch'

let quantity: 50 = 50;    //can only be 50
let weight: 50| 51 = 50;  //can only be 50 or 51.
```
> Exact values for the variable, these can be assigned in the type 


#### Nullable Types
```TypeScript
function greet(name: string | null): void {
  if (name === null) {
    console.log("Hello, my friend.");
  } else {
    console.log("Hello " + name);
  }
}

greet("Omar");
greet(null);
```
>If null value for parameter could be used, use the union type.


#### Generics

>Used to make the function have a type to fix issues around functions used for generic types.
>The function here works for both strings and numbers as it infers the type.
```JavaScript
function insertAtBeginning<T>(array: T[], item: T){
	const newArray = [item, ...array];
	return newArray;
}

const demo = [1,2,3];
const updatedDemo = insertAtBeginning(demo, 5);

const demo1 = ["1", "2", "3"];
const updatedDemo1 = insertAtBeginning(demo1, "5");

```

---
