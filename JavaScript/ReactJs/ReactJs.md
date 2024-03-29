
### General Notes

> JavaScript library for building user interfaces.
> Client side JavaScript.
> Manipulate web pages after they are loaded.
> [ReactJs](https://reactjs.org/).

> Single Page Application (SPA).
> Server only sends one HTML page, then React takes over and changes the DOM.
> This file is the `index.html` file.

> This is an alternative for [[Angular]].
> [[NodeJs]] needs to be installed.
> [[Node Package Manager (NPM)]] manages the dependancies.
> There is a `package.json` that holds metadata about the project, contains the Development Dependencies, and uses [[Semantic Versioning]].

---
### Create a Project

>Navigate to folder.

```bash
npx create-react-app <app-name>
```

---
### Run the Project

>Must be in the folder.

```bash
npm start
```

> Should open a website on the `localhost` with [[Port]] 3000. 

---
### [[JavaScript/ReactJs/Components]]

> The `index.js` file is the first file that gets executed.
> In it, we call the components we created and render them to the `index.html` file in a specific place, for example with `id`.
> The components are simply JavaScript functions that return JSX.

---
### JSX

> This is when we include HTML code inside JavaScript.
> Not understood by the browser.
> Can only return 1 element in JSX code. This element can then contain several other elements.

---
