
### General Notes

> JavaScript library that works similar to [[ReactJs]].
> Works together with `expo` to be able to edit and view code on the fly.

Documentation: [Link](https://reactnative.dev/docs/getting-started).

---

### Download and Setup With `expo`

Make sure [[NodeJs]] and [[Node Package Manager (NPM)]] are installed.

```bash
npx create-expo-app <project-name>
```
> This command creates a new `expo` project that can be edited using react native.

Then go to the directory of the project with its name to work.

> To be able to run on the web:
```bash
npx expo install react-dom react-native-web @expo/webpack-config
```

---

### Running the Project

```bash
npx expo start
```

A QR code is generated that can be scanned by phone. The expo app on the phone opens the live development server where changes to the code are observed.

> The main entry point of the code can be changed from the `AppEnry.js` file.
> This file is located in: `node_modules/expo/AppEntry.js`.

---
