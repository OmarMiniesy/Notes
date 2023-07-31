
### General Notes

> This policy prevents JavaScript code from playing with resources from a different origin.
> For JavaScript to access any resource, the Hostname, [[Protocol]], and [[Port]] must match.

> CSS stylesheets, images, and scripts are loaded by browser without using the SOP.
> SOP is used when [[HTTP]] requests are initiated from within client side scripts.
> Defines the boundaries of client side attacks.

> Allows domains to issue requests to other domains but not to access responses.

---

### Origin

>The origin is defined by the 
* [[Protocol]]
* Host
* [[Port]]

> The SOP is used to isolate requests coming from different origins.

---

### How does it work?

> [[HTTP]] requests sent across domains, [[Cookies]] are also sent as part of the request.
> The SOP prevents the transfer of these cookies, such as [[Sessions]] cookies, across domains.

> The SOP controlls access that JavaScript code has to content loaded cross-domain.
> JavaScript won't be able to read or play with data such as images, media, and javascript transmitted cross-origin.

> SOP is more relaxed with cookies, meaning they are accessible from all subdomains of a site, [[SameSite#What is a Site ?]], even though each subdomain is a different origin. 
> Using the `HTTPOnly` cookie flag can help defend.

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

#### Cross Origin Resource Sharing ([[CORS]])

> Allows browser to bypass SOP to access some resources.
> Using custom [[HTTP]] headers.

---



