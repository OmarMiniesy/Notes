

### General Notes

> One way to handle [[Synchronous and Asynchronous]] issues with returning values from functions

---

### Method

> Add a callback function parameter in the function
* Add the callback parameter
* Call the callback function with the return value of this function
```JavaScript
function getUser(id, callback) {
  setTimeout(() => {
    console.log("Reading a user from a database...");
    callback({ id: id, username: "mins" });
  }, 2000);
}
```

> When calling the function, add the callback function
* Add a parameter to hold the return value of the callback function
* Can then use this parameter
```JavaScript
getUser(1, (user) => {
  console.log(user);
});
```

---

### Nesting 

> When calling the functions, the callback functions can be nested, this will make the second function `getRepo` wait for its time plus the time of the `getUser` function.
```JavaScript 
getUser(1, (user) => {
  console.log(user);
  getRepo("mins", (repos) => {
    console.log(repos);
  });
});
```

>This is important because calling multiple times for data from a database could need to wait all this added time

---

### Callback Hell and Named Functions

> This nested structure can become too complex
> To solve this issue, named functions were introduced.

```javaScript
getUser(1, (user) => {
  console.log(user);
  getRepo("mins", (repos) => {
    console.log(repos);
  });
});
```

1. Given this code, we can simplify it by starting from inside out. 
2. Take the anonymous function `(repos) => {console.log(repos)}` and name it 
```JavaScript
function getRepos(repos){
	console.log(repos);
}
```

3. Then place it in the main given code as an instance, not a call
```JavaScript
getUser(1, (user) => {
  console.log(user);
  getRepos("mins", displayRepos);
});

function displayRepos(repos){
	console.log(repos);
}
```

4. Repeat the same steps 
```JavaScript
getUser(1, displayUser);  //simplified callback structure.

function displayUser(user) {
  console.log(user);
  displayRepos("mins", getRepos);
}
function displayRepos(repos){
	console.log(repos);
}
```

---

