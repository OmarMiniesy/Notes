
### General Notes

> One way to handle the issues with [[Synchronous and Asynchronous]] function returns
> Promise is an object that holds the eventual result of an asynchronous operation
> This result can be something correct returned or an error

> Should be used to replace all [[Callbacks]] 

---

### Operation

> Promise object has resolve to hold the result and reject to hold the error
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
> Inside it place the asynchronous work, and the return of this prmise is the resolve or reject

2. Consuming a Promise
```javascript
const p = getUser(1);
p.then((user) => console.log(user));
```

> To chain promises

