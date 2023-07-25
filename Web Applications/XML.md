
### General Notes

> eXtensible Markup Language.
> Language used for storing and transporting data.

> No predefined tags, user-created tags to customize and define the data.

---

### XML Entity

> Represent a data item in XML format.
> To call on it, `&` + its name + `;`.

> So the less than sign, or `<` as an XML entity is `&lt;`. View [[Web Encoding]].

---

### XML DTD

> Document Type Definition.

> Contains declarations that defines the structure of an XML document and the data types it has.
> Declared usin the `DOCTYPE` elemenet at the start of the XML document.

> DTD can be external, internal, or hybrid.
* External DTD: The DTD is loaded into the document.
* Internal DTD: The DTD is self-contained within the document.
* Hybrid DTD: Both.

---

### Custom XML Entity

> To create a custom XML entity within DTD.
```XML
<!DOCTYPE foo [ <!ENTITY myentity "its value"> ]>
```
> Whenever `&myentity;` is called, it will be replaced with `its value`.


###### XML External Entity

> Custom entity whose definition is outside the DTD they are declared.
> Uses the  `SYSTEM` keyword and specifies a URL from which the definition is loaded, or from a file path.
``` XML
<!DOCTYPE foo [ <!ENTITY ext SYSTEM "http://normal-website.com" > ]>
<!DOCTYPE foo [ <!ENTITY ext SYSTEM "file:///path/to/file" > ]>
```
> `ext` is the name of this entity, to use it: `&ext;`.

###### XML Parameter Entity

> Special kind of XML entity which is only referenced elsewhere within the same entity DTD.
```XML
<!DOCTYPE foo [ <!ENTITY % ext SYSTEM "file:///path/to/file" > ]>
```
> Includes the `%` character before the entity name.
> And referenced using the `%` instead of `&` character: `%ext;`.

> When defining entities inside each other, we use the [[Web Encoding]] for special characters.
```XML
<!DOCTYPE foo [ <!ENTITY &#x25; ext SYSTEM "file:///path/to/file" > ]>
```
> Can replace `%` with its entity encoded version: `&#x25;`.

---

