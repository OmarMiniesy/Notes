
### General Notes

> Directives are instructions in the DOM used by [[Angular]]
> [[JavaScript/Angular/Components]] are a kind of directives with a template
> There are directives without templates, these are added with the attribute selectors
> Directives are defined using the `@Directive` decorator

---

### Examples

#### 1. ngIf Directive

> Structural directive, can change the DOM, so a `*` is needed before its name when added
> The qoutes contain the boolean expression that resolve the `ngIf`

```HTML
<p *ngIf="<function in typescript file"> TEXT </p> 
```

> We can add an else block
```HTML
<p *ngIf="<function in typescript file> ; else minsMark"> TEXT </p> 
<ng-template #minsMark> <p> The other TEXT</p> </ng-tempalte>
```
* the second line is like a placeholder that angular uses, it has the identifier `minsMark`
	* This identifier is preceded by a `#`
* the first line has an else statement that calls this `ng-template` by its name

#### 2. ngStyle Directive

> Attribute directive, can change the element they were placed on.
> Dynamic styling by changing the CSS style itself
> Used by placing `[]` around the `ngStyle` directive. It is not [[Property Binding]], we are binding to a property of the directive.

```HTML
<p [ngStyle] = "{'background-color': '<typescript function>'}"> TEXT</p>
```
* It takes a JavaScript object inside the qoutation marks (key-value pairs)

#### 3. ngClass Directive

> Attribute directive, can change the element they were placed on.
> Dynamically add or remove CSS classes.
> Used by placing `[]` around the `ngClass` directive.

```HTML
// assume there is a css class called mins
<p [ngClass] = "{'mins': '<typescript function>'}"> TEXT</p>
```
* Evaluates to true or false
* This evaluation can then remove or keep the CSS class of this element.

#### 4. ngFor Directive

> Structural directive, can change the DOM, so a `*` is needed before its name when added
> Can add [[JavaScript/Angular/Components]] if used inside a component selector
> Works using a for loop

```HTML
// assume components is an array of the components in the typescript file and the number of components keeps increasing. The for loop will dynamically adapt and create these components without having to do them myself.
<component-name *ngFor = "let x of components"></component-name>
```

---
