
### General Notes

>TypeScript is a programming language built on top of JavaScript, meaning it is JavaScript and more
>Every Javascript file is a typescript file
>JavaScript with type checking

> Typescript needs to be compiled into javascript to be executed on browsers (Transpilation)

> `.ts`
___

### Advantages

* Static Typing: Knowing the type of variables and value before compilation
* Dynamic Typing: Changing the type and value of variables before runtime

>**TypeScript is Statically Typed**, which is better to catch bugs and reduce complexity

* Code completion
* Refactoring
* Shorthand Notations
 
---

### Installing TypeScript using [[Node Package Manager (NPM)]]

```bash
sudo npm i -g typescript
```

* `i` for install
* `-g` for global access

##### Checking Installation and Version

```bash
tsc -v 
```


___

### Executing TypeScript File

```bash
tsc <path_to_file>.ts
```

> This will compile the `.ts` file into a `.js` file. 

or, if the `"rootdir"` option is uncommented in the configuration file, it automatically targets it without specifying the path to the source files.
```bash
tsc
```

> Then execute the compiled JavaScript code 
```bash
node <path_to_file>.js
```
___

### TypeScript Configuration File

> Create the configuration file in `JSON` format called `tsconfig.json`
```bash
tsc --init
```

> We can uncomment whatever options we need or change them: 

* `"target": "es20xx`  : Change the JavaScript compiler, higher year means better code but might not be supported by all browsers
* `"rootdir": "./<path>"` :  Change the path of the TypeScript source files
* `"outdir": "./<path>"`:  Change the path of the JavaScript output files
* `"removeComments": true` : Adding comments or removing comments from JavaScript result files
* `"noEmitOnError": true` : Disable emitting files if any type checking errors are reported

___
