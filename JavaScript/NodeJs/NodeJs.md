
### General Notes

The framework used to create the backend of websites.
- A javascript compiler.
- Manages the authorization, [[Application Programming Interface (API)]]s, Configuration, and more.

---
### Initialize a Node Project

To start a node project, we need a `package.json` file. This has all the metadata needed for our project.

```bash
npm init --yes
```
> This creates a node project with default values using the `--yes` flag.

---
### Understanding `package.json`

This is how a `package.json` file looks like:

```json
{
  "name": "backend",
  "version": "1.0.0",
  "description": "",
  "main": "index.js",
  "scripts": {
    "test": "echo \"Error: no test specified\" && exit 1"
  },
  "keywords": [],
  "author": "",
  "license": "ISC",
  "dependencies": {
    "express": "^4.18.2",
    "mysql": "^2.18.1",
    "nodemon": "^3.0.3"
  }
}
```

* The project name, version, and description are defined.
* The main path that contains the main file of the project is defined in `main`.
* The `scripts` section defines scripts that can be run with `npm run <name>`.
```json
"scripts":{
	...,
	"start": "node index.js"
}
```
> If we add a script called `start` and its definition is `node index.js`, this means if we type in the terminal `npm run start`,  this exact command will be executed.

We can also define the environment in the script which helps setting the [[Environment Variables]] for the project:
```json
"start-dev": "NODE_ENV=development node index.js"
```
> What this does, is set the `NODE_ENV` environment variable to `development`.

* Listed as well are the Development Dependencies or libraries that are used to run the project. These are the ones installed using [[Node Package Manager (NPM)]].

---
