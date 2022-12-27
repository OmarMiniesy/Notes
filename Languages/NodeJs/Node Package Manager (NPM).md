

>Used to install packages and building blocks for node [npmjs](https://www.npmjs.com/)

> `-g` is the global flag. Append it to any command to play with packages on the global scale, not just in a single project.
---

### Check NPM Version

```bash
npm -v
```

> To change version
```bash
npm i -g npm@<version_num>
```

> To update
```bash
npm i -g npm
```

---

### Package.json

> File that contains metadata about the node project. Should be created before installing any node packages
``` bash
npm init --yes  
```

>`--yes` to accepts default values

> This package.json file also contains [[Development Dependencies]] modules.

> Node packages also have their own package.json file with all the metadata of that module. This package can be viewed by
```bash
npm view <package-name>
```

---

### Install Packages

> When a node module is installed, it is installed in a directory called node_modules and the module is added to the package.json file with its version. Second command is to install a specific version of a module.

```bash
npm i <package_name>
npm i <package_name>@<version_num>
```


> Installing all packages already present in a project in the `package.json` file. Downloads the versions based on [[Semantic Versioning]]
```bash
npm i
```

> `node_modules` file shouldnt be included when saving the project in a GitHub repo, use the [[gitignore]] file.

---

### Listing Intsalled Packages

>Used to check the versions of all packages installed

>List all packages along with their dependancies in a tree format
```bash
npm list 
```

>List all packages that are being used by the project without their dependancies
```bash
npm list --depth=0
```

---

### Uninstall Packages

>Will remove it from package.json file and from the node_modules folder.
```bash
npm un <package_name>
```

---

### Update Packages

> Check for outdated packages
```bash
npm outdated
```

> Update a specific package
```bash
npm upgrade <package_name>
```

> Will change the version in the package.json file of the project and the module itself. 
> Will only update to the next available version to not break the project. Can be overruled through

___