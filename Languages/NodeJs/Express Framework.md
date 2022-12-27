
### General Notes

> Express is a framework used to handle [[Application Programming Interface (API)]]s with a good structure
> The documentation at [Expressjs - 4.x](https://expressjs.com/en/4x/api.html) has all the functionalities

---

### Installing Express using [[Node Package Manager (NPM)]]
```bash
npm i express
```

---

### Running Using [[Nodemon Module]] 

> Helps to quickly restard server without having to rerun the file.
```bash
nodemon <file_name>
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

>This is a method for specifiying routes, the get method and the url (endpoint). The callback function is the route handler.

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
> When a GET request fails to get the required object or path, HTTP status code of 404 is called.
```JavaScript
const express = require("express");
const app = express();

courses = [{id: 1, name: "course1"}, {id: 2, name: "course2"}];

app.get("/courses", (req, res) => { //display all the courses
	res.send(courses);          
});

app.get("/courses/:id", (req, res) => { //find course with specific id
  const x = courses.find((c) => c.id === parseInt(req.params.id));
  if (!x) {
    res.status(404).send("The course with the given ID was not found");
  } else {
    res.send(x);
  }
});

const port = process.env.PORT || 3000;
app.listen(port);
```
