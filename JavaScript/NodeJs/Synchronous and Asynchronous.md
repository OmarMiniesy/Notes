### Synchronous

Synchronous code is **blocking**.
- Wait for the first statement to finish then carry on execution of the next statement.

---
### Asynchronous 

Asynchronous code or functions are **non-blocking**.
- They don't follow the order of execution

Example: `setTimeout((function), (timeout))`.
- Schedules a task that does the function after a timeout.

> Can cause issues with returning values and assigning variables

To solve this issue: 
 1. [[Callbacks]]
 2. [[Promises]]
 3. [[Await-Async]]


---
