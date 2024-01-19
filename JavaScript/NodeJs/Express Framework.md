
### General Notes

> Express is a framework used to handle [[Application Programming Interface (API)]]s with a good structure.
> The documentation at [Expressjs - 4.x](https://expressjs.com/en/4x/api.html) has all the functionalities.
> Use Postman to test.

---
### Installing Express using [[Node Package Manager (NPM)]]
```bash
npm i express
```

---

### Basic Route Handling

>Load the module and create an instance called app. Can use the [[HTTP]] verbs.
```JavaScript
const express = require("express");
const app = express();

app.get(<"url">, <callbackfunction (req, res)>);

app.get("/", (req, res) => {
	res.write("Hello");
	res.end()
});

app.post();
app.delete();

const port = process.env.PORT || 3000;
app.listen(port);   //port to listen on localhost, if it is not set as an environment variable, use 3000.

```

>This is a method for specifiying routes, the get method and the url (endpoint). 
>The callback function is also called the route handler.

>The [[Port]] is taken from the environment variable `PORT`.
>We set environment variables: `process.env.NAME=VALUE`.

---

### Using parameters

> Route parameters: for essential or required data. These are in the endpoint path itself.
> Query parameters: for optional features. These are after the question mark at the end.

> The `req.params` and `req.query` are objects that hold their data in key-value pairs

>Route Parameters
``` JavaScript
const express = require("express");
const app = express();

app.get("/course/:courseId", (req, res) => {
	let x = req.params.courseId;   //x is a variable that holds the route parameter courseId
	res.send(x);                   //will display the value of the parameter
});

app.get("/course/:courseId/:sectionId", (req, res) => {
	res.send(req.params);          // will display values of all parameters.
});

const port = process.env.PORT || 3000;
app.listen(port);
```

>Query Parameters
```JavaScript
const express = require("express");
const app = express();

app.get("/course/", (req, res) => {
	res.send(req.query);          // will display values of all query parameters.
});

const port = process.env.PORT || 3000;
app.listen(port);
```

---

### [[HTTP]] GET 

> When a GET request is met properly, HTTP status code of 200 is called.
> When a GET request fails to get the required object or path, HTTP status code of 404 is called
```JavaScript
const express = require("express");
const app = express();

courses = [{id: 1, name: "course1"}, {id: 2, name: "course2"}];

app.get("/courses", (req, res) => { //display all the courses
	res.send(courses);          
});

app.get("/courses/:id", (req, res) => { //find course with specific id
  const x = courses.find((c) => c.id === parseInt(req.params.id));
  if (!x)
    return res.status(404).send("The course with the given ID was not found");
  res.send(x);
});

const port = process.env.PORT || 3000;
app.listen(port);
```

---

### [[HTTP]] POST

>If input is invalid, can return HTTP status code 400 for bad request.
>Validate input using the [[JOI Module]].
``` JavaScript
const express = require("express");
const Joi = require("joi");
const app = express();

app.use(express.json());   //to be able to stringify the request body ( creates req.body)

courses = [{id: 1, name: "course1"}, {id: 2, name: "course2"}];

app.post("/courses", (req, res) => {
	const schema = Joi.object({name: Joi.string().min(3).required()});
	const result = schema.validate(req.body);
	if (result.error){
		return res.status(400).send(result.error); 
	}
	
	const course = { id: courses.length + 1, name: req.body.name};
	courses.push(course);
	res.send(course);
})

const port = process.env.PORT || 3000;
app.listen(port);
```

---

### [[HTTP]] PUT

1. Look up the exact element we want to update, if not found then return
2. Validate this element, if not valid then return
3. Update this element

```JavaScript
const express = require("express");
const Joi = require("joi");
const app = express();

app.use(express.json());   //to be able to stringify the request body

courses = [{id: 1, name: "course1"}, {id: 2, name: "course2"}];

app.put("/courses/:id", (req, res) => {
	
	const x = courses.find((c) => c.id === parseInt(req.params.id));
	if (!x)
		return res.status(404).send("The course with the given ID was not found");
		
	const schema = Joi.object({name: Joi.string().min(3).required()});
	const result = schema.validate(req.body);
	if (result.error)
		return res.status(400).send(result.error);
	
	x.name = req.body.name;
	res.send(x);
})

const port = process.env.PORT || 3000;
app.listen(port);

```

---

### [[HTTP]] DELETE

1. Look up the element, if not exist then return 404 error status code
2. Delete the element
3. Return the deleted element

```JavaScript
const express = require("express");
const Joi = require("joi");
const app = express();

app.use(express.json());   //to be able to stringify the request body

courses = [{id: 1, name: "course1"}, {id: 2, name: "course2"}];

app.delete("/courses/:id", (req, res) => {
  const x = courses.find((c) => c.id === parseInt(req.params.id));
  if (!x) return res.status(404).send("The course with the given ID was not found");  

  const index = genres.indexOf(x);
  genres.splice(index, 1);  

  res.send(x);
});

const port = process.env.PORT || 3000;
app.listen(port);
```

---

### Middleware Functions

> Stops the request-response cyle and returns a response object, or passes control to another middleware function.
> The route handler is a middleware function as it terminates the cycle and returns a response object.

> Custom middleware functions.
```JavaScript
// in logger file
function logger(req, res, next){
	console.log("logging");
	next();
}

//in main file
app.use(logger());
```
What happens here is that the `app.use` is a  function that calls a middleware function `logger`. This middleware function executes its instructions `console.log()` and then proceeds to the `next()` function. Without this `next()` function, the code will hang. Once the `next()` is called, flow continues again in the main file, which is the main idea of middleware.

>Builtin middleware functions.
```JavaScript
app.use(express.urlencoded( {extended: true} ));
```
This `urlextended` middleware function allows for the encoding of  parameters in the payload in key-value pairs. 
>`key=value&key=value` in the request urls.

```JavaScript
app.use(express.static(<foldername>));
```
This `static` middleware function allows to host static content, such as images or text files. Add the name of the folder with the static content as the parameter. The static content will be visible from the root url of the site and not under the folder name.

> Third party middleware functions can be found [Middleware Functions](https://expressjs.com/en/resources/middleware.html)
> only use them if necessary as they impact the performance.

---

### Proper Structuring

1.  Place all the routes that begin with the same path in separate files in one folder called `routes`.
2. Place all the loggers and middleware functions in separate files in one folder called `middlewares`.
3. ...

> In the file with the routes that begin with `/api/courses` called `courses.js` in the routes folder.  
```JavaScript
const express = require('express');
const router = express.Router();   //added this line and changed app to router
router.get('/', (req, res) => {    //change app to router and change /api/courses to /
  res.send(genres);
});
module.exports = router;
```

> In the `index.js` file, 
```JavaScript
const courses = require('./routes/courses');
app.use('/api/courses', courses); //the first parameter is the route and the second is the variable that holds the required module.
```

---
