
### General Notes

> This policy prevents JavaScript code from playing with resources from a different origin.
> For JavaScript to access any resource, the Hostname, [[Protocol]], and [[Port]] must match.

> CSS stylesheets, images, and scripts are loaded by browser without using the SOP.

> SOP is used when [[HTTP]] requests are initiated from within client side scripts.

> Defines the boundaries of client side attacks.

---

### Origin

>The origin is defined by the 
* Protocol
* Host
* Port

> The SOP is used to isolate requests coming from different origins.

---

### Exceptions 

#### window.location

> Document can *always* write the `location` property of another document.
> The `window.location` can be used to get current page URL and redirect browser to new page.

> Two documents can write the location property of one another even if they are not of the same origin.
> Two documents can be related if they are embedded in one another using the `iframe` element.

#### document.domain

> Describes the domain portion of the document. The part of the URL between `http://` and anything in the end after the first `/`.

> Documents can change their domain except for the highest level domain. This allows a document to partially change its origin.

#### Cross Window Messaging

> Allows different documents regardless of SOP to communicate.

#### Cross Origin Resource Sharing (CORS)

> Allows browser to bypass SOP to access some resources.
> Using custom [[HTTP]] headers.

---



