
### General Notes

> JavaScript framework that helps build reactive single page applications. (SPA)
> Changes the DOM, the HTML code during runtime.
> [[NodeJs]] is used to bundle and optimize code.
> [[Node Package Manager (NPM)]] is used to manage dependancies.
> Uses [[TypeScript]]

---

### Installation using [[Node Package Manager (NPM)]]

```Bash
npm i -g @angular/cli
```

---

### Creating an Angular Project

> Creates an angular project folder with the name. No white space allowed or the word `test` in the name
> `--no-strict` to make it easier for making projects (optional). Can be changed in the `tsconfig.json` file
```bash
ng new <project_name> --no-strict
```

> Complete the project setup

>To start the server, runs the project on the localhost.
```Bash
ng serve
```


> If a project is cloned by github, the dependancies and [[Modules]] used need to be installed
```bash
npm i 
```
> If this brings up the socket and proxy error, run this command then install again
``` bash
npm config set registry http://registry.npmjs.org/
```

---

### CSS Styling 

> Use a CSS bootstrap package to help with styling

1. Download it using [[Node Package Manager (NPM)]] `npm i bootstrap`
2. Add the path of the `bootstrap.min.css` file to the `angular.json` file in the css section before the `src/styles.css` file to override it.

---
