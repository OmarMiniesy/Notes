
### General Notes

Works on [[Promises]] and makes it easier for writing Asynchronous code.

---
### Usage

Instead of using the `.then` and `.catch` functions and chaining.
- Simply use normal Synchronous code but place the `await` keyword.

> For any function that the `await` keyword is used in, decorate it with `async`.

```JavaScript
function mins(a) {
  return new Promise((resolve, reject) => {
    setTimeout(() => {
      resolve(a * 60);
    }, 1000);
  });
}

async function asyncMins(a) {
  const result = await mins(a);
  console.log(result);
}  

asyncMins(5);
```

- Here, the function `mins` returns a promise.
- The function `asyncmins` consumes the promise by storing its output in a variable.
- Decorate the variable with `await`, and the function with `async`.

---

### Errors

- Using a `try-catch` block to catch errors.

> Errors occur if promises are rejected not resolved.

```JavaScript
function mins(a) {
  return new Promise((resolve, reject) => {
    setTimeout(() => {
      reject(new Error('idk'));
    }, 1000);
  });
}

async function asyncMins(a) {
  try{
    const result = await mins(a);
    console.log(result);
  }
  catch (err) {
    console.log("error: ", err.message);
  }
}  

asyncMins(5);
```

---
