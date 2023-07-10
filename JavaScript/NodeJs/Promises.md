
### General Notes

> One way to handle the issues with [[Synchronous and Asynchronous]] function returns in [[NodeJs]].
> Promise is an object that holds the eventual result of an asynchronous operation.
> This result can be something correct returned or an error.

> Should be used to replace all [[Callbacks]].

---

### Operation

> Promise object has resolve to hold the result and reject to hold the error.
```JavaScript
const p = new Promise((resolve, reject) => {
	//asynchronous work
	//condition to choose between either, or to be placed inside async functions
	resolve(1);
	reject(new Error("message")); //error object with message holding value "message"
});


p.then((result) => console.log('Result', result)); //to recieve result
p.catch((err) => console.log('Error', err.message)); // to catch error
```

---

### Creating a Promise and Consuming it

1. Creating a Promise
```JavaScript
function getUser(id) {
  return new Promise((resolve, reject) => {
    setTimeout(() => {
      console.log("Reading a user from a database...");
      resolve({ id: id, username: "mins" });
    }, 2000);
  });
}
```
> Return a promise function with parameters resolve and request.
> Inside it place the asynchronous work, and the return of this prmise is the resolve or reject.

2. Consuming a Promise
```javascript
const p = getUser(1);
p.then((user) => console.log(user));

getUser(1).then(user => console.log(user));
```
> Whats inside the bracket, `user`, is the returned data from the promise `p`.

##### Chaining Promises

> If the function being called by `then` while consuming a promise is also returning a promise, then we cain chain `.then` and `.catch`.
```JavaScript
getUser(1).then(user => asyncFunc(user))
		.then(nextUser => console.log(nextUser));
```

> Always good practice to attach a `.catch()` in the end for any errors.
```javaScript
getUser(1).then(user => asyncFunc(user))
		.then(nextUser => console.log(nextUser))
		.catch(err => console.log(err.message));
```
> `.message` works if `err` is of type `Error`.

---

### Parallel Promises

> Running multiple promises at almost the same time.
> Then consuming them one once they all finish.

```JavaScript
function mins(a) {
  return new Promise((resolve, reject) => {
    setTimeout(() => {
      resolve(a * 60);
    }, 1000);
  });
}

function mins1(a) {
  return new Promise((resolve, reject) => {
    setTimeout(() => {
      resolve(a * 60);
    }, 3000);
  });
}
Promise.all([mins(2), mins1(3)]).then((res) => 
  console.log(res);
});
```
> Since `mins` takes 1 second and `mins1` takes 3 seconds, the result of the `console.log` will be displayed after 3 seconds.

> To consume promises once the first one finishes use `.race()`.
``` JavaScript
function mins(a) {
  return new Promise((resolve, reject) => {
    setTimeout(() => {
      resolve(a * 60);
    }, 1000);
  });
}

function mins1(a) {
  return new Promise((resolve, reject) => {
    setTimeout(() => {
      resolve(a * 60);
    }, 3000);
  });
}
Promise.race([mins(2), mins1(3)]).then((res) => 
  console.log(res);
});
```
> Will display after only 1 second the result of the finished promise

---
