

> In [[Angular]], adding an image uses [[Property Binding]]

1. Create a variable that holds the path of the image in the `assets` folder. Must go back one directory.
```TypeScript
logo: string = "../assets/logo.png";
```
>[[Components]] typescript file

2. Create the `img` element in the `HTML` file and add the `src` attribute. Using [[Property Binding]] add the variable created in step 1.
```HTMl
<img [src]="logo" alt="" />
```
> [[Components]] HTML file
---
