
### General Notes

These are configuration settings and sensitive variables such as [[Application Programming Interface (API)]] keys, database credentials, or passwords.

> These change depending on the type of environment the project is currently in.

More like at which phase or stage the project is at:
* Development
* Production

This is the case since in different phases of software development, there are different resources and databases being played with. If we play with the production database whilst development and something goes wrong, this is a disaster. Therefore, we have a development database to test on.

---

## Handling Environment Variables

There are multiple ways to handle environment variables in the project, and these also change depending on the software used. This is for [[NodeJs]] projects.

### Using `dotenv` Package

> Installing the `dotenv` package using [[Node Package Manager (NPM)]].
```bash
npm i dotenv
```

> Adding the `NODE_ENV` and desired environment in the `package.json` scripts section:
```JSON
  "scripts": {
    "start-dev": "NODE_ENV=production nodemon index.js",
    "start-prod": "NODE_ENV=development nodemon index.js"
  },
```
* This ensures that whilst running the `start-dev` command, the environment is set to `development`. This can be used in the rest of the files in the project to get their correct environment variables.

> Create the actual files that contain the environment variables:
```
.env.development
.env.production
```
* These files should be added to the [[gitignore]] file when pushing to github to avoid publishing secrets.

> In the main file of the project, include the `dotenv` package and configure which variables are to be used based on the environment set in `NODE_ENV`.
```javascript
const dotenv = require("dotenv");

const envFile = `.env.${process.env.NODE_ENV}`;
dotenv.config({ path: envFile });
```

Now we can start using the environment variables for the respective environment in the project.

> `.env.development`
```
PORT = 5555
```

> With a development environment:
```javascript
const port = process.env.PORT;
console.log(port);

// SHOULD OUTPUT 5555
```

---

