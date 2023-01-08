
### General Notes

> One of the builtin [[NodeJs]] [[Modules]]
> Helps manage the [[Configuration]] of projects to properly set up the environments

---

### Installation using [[Node Package Manager (NPM)]]

```Bash
npm i config
```

---

### Usage

> development.json
```JSON
{
	"name": "app",
	"mail": {
		host: "app.com"
	} 
}
```

>index.js
```javaScript
const config = require('config');
console.log(`app name: ${config.get('name')}`);
console.log(`email host: ${config.get('mail.host')}`);
```

> For this to work, [[Environment]] must be set to development through the environment variables.
> Works the same for the [[Configuration]] custom-environment-variables.json file.

---
