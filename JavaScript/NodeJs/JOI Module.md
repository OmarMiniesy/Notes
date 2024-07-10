
### General Notes

> One of the builtin [[NodeJs]] [[Modules]]
> Used to validate inputs in complex objects and return error messages, as well as [[HTTP]] status codes

___

### Installation using [[Node Package Manager (NPM)]]

```bash
npm i joi
```

---

### Importing and Usage

>Its a class, so using the [[Modules]] method for using classes, we need to import the class then create an instance of the class.

`const Joi = require("joi");`

---

### Schemas and Validation

> These are used to define the validation.
``` JavaScript
const Joi = require("joi");
const schema = Joi.object({
	name : Joi.string().min(3).required();   //name must be required and min length of 3 chars
});
```

>To validate, create an object and use the `validate` function with the `request.body` and the schema defined
```JavaScript
const result = schema.validate(req.body);
```

---

### To check for errors

```JavaScript

if (result.error){
	res.status(400).send(result.error);
	return;   //to stop execution to display error
}

```

---
