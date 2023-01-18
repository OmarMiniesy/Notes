
### General Notes

> A suite of many pre-built [[Angular]] [[Components]]
> Styling of google material design and logic implemented within angular components

> CDK (Component Development Kit) is a separate package that contains utility functionalities and base components.
> CDK + Angular Components + Google Design = [Angular Material](https://material.angular.io/)

> [Angular Material Components](https://material.angular.io/components/categories)
> Contains the components that can be added to an angular project.

---

### Setup

Add Angular Material to project
```bash
ng add @angular/material
```

>This changes several files, such as the `index.html`, the `styles.css`, `app.module.ts`, and configuration files.

> The theme can be changed from the `angular.json` file.
---

### Adding Components

1. Import the module for the component needed in the `app.module.ts` file. Name is usually the component name without the dash, capitalize starting letters, and add Module to the end.
2. Add this name to the `imports` array as well.

```JavaScript
//component needed is mat-button
import {MatButtonModule} from '@angular/material/button';

@NgModule({
...
imports: [..., MatButtonModule, ...],
...
})
```
> `app.module.ts`
> To get the proper file name, use intellisense `ctrl + space`.

3. Add it in an `HTML` file with its selector 
```HTML
<button mat-button> BUTTON </button>
```

> There are variants as well that can be used, these do not need any extra imports. The main component should only be imported and included.

---
