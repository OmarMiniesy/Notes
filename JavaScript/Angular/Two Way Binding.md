
### General Notes

> Is by combining both [[Event Binding]] and [[Property Binding]]

---

### Setup

> `ngModel` directive needs to be enabled

1. add `FormsModule` to the `imports[]` array in the `AppModule.ts` file
2. add the import from `@angular/forms` in the `AppModule.ts` file 
```typescript
import { FormsModule } from '@angular/forms';
```

---

### Usage

```HTML
<input type = "text" [(ngModel)]="serverName">
<p> {{ serverName}} </p>
```
* add both `[]` and `()` and using the `ngModel` directory
* This allows for the serverName property to change at the same time with the input event

> This however changes all the values of `serverName` in the template

---
