
### General Notes

A javascript file is a module, and each file has its own variables and functions in its scope

```javascript
console.log(module)   //will print in JSON format the attributes of the file (module)
```

Result: 

```JSON
Module {
  id: '.',
  path: 'C:\\Computer Science\\New folder',
  exports: {},
  filename: 'C:\\Computer Science\\New folder\\app.js',
  loaded: false,
  children: [],
  paths: [
    'C:\\Computer Science\\New folder\\node_modules',
    'C:\\Computer Science\\node_modules',
    'C:\\node_modules'
  ]
}
```

---

### Exporting Functions and Variables

- The exports key contains the variables and the functions that we want to be accessed by another module. Will be exported as an object.
```JavaScript
module.exports.exportName = functionName;
module.exports.exportName = variableName;
```

- Export as function only
```JavaScript
module.exports = functionName;
```
---

### Loading  a Module

- If exported is object:
```JavaScript
const mod = require('./<path_to_module>') //import the module into a const to avoid errors. 

console.log(mod); //will print the exported variables and functions. It is an object.

//to use the variables and functions in the imported module, name of variable holding the import and dot operator.
mod.<func_in_import_module>();
mod.<variable_in_imported_module>();
```

- If exported as function only:
```JavaScript
const mod = require('./<path>')

mod(<parameters>);
```

---

### Built In Modules

> From [Node.js](https://nodejs.org/dist/latest-v18.x/docs/api/)

Using the parameters for the `require` function assumes default names for the built in modules. If they are not there, then it will check for the actual files present in the directory.

- To use the functions:
```JavaScript
const x = require('module');
let y = x.function();
```

- Classes have uppercase letters in their names. To use classes, we need to instantiate
```JavaScript
const ClassName() = require('module');
const x = new ClassName();
```

___
