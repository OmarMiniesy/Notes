
### General Notes

> Constraints on who can perform actions or access resources.
> Dependant on [[Authentication]] and [[Sessions]] management.

> Vertical, Horizontal, and Context-dependant access controls.

---

### Vertial Access Control

> Mechanisms that restrict access to sensitive resources that aren't available to all users.
> Different types of users have access to different resources.

#### Vertical Privilege Escalation

> User gaining access to functions that they are not permitted to access.

##### Methods:

###### 1. Unprotected functionality

> Trying to access the admin page through the URL directly.
> Looking for sensitive unprotected pages.
```
https://insecure-website.com/admin
```
> If this doesn't work, browse to the `robots.txt` to check for the disclosed admin page.
```
https://insecure-website.com/robots.txt
```
> Otherwise, the URL can be brute forced using a dictionary attack. [[Directory and File Enumeration]].
> Check JavaScript scripts to check if anything is disclosed there. Some websites use scripts to show different UI if the user is an admin.

###### 2. Parameter-based 

> Applications can determine the roles and rights at login by storing this data in user-controllable locations.

* Hidden body parameter.
* [[Cookies]].
* Query string paremeter in the URL. (`?parameter=value`).

> User can modify these values and gain admin functionality.

###### 3. Platform Misconfiguration

> Some applications restrict access to specific URLS and [[HTTP]] methods based on user role.
```
DENY: POST, /admin/deleteUser, managers
```
> Denies `POST` methods on the URL `/admin/deleteuser` to `manager` users.

> These can be overriden using [[HTTP]] headers.
* `X-Original-URL: /admin/deleteUser`.
* `X-Rewrite-URL: /admin/deleteUser`.

> Can be used to bypass these rules.



---

### Horizontal Access Control

> Mechanisms that restrict access of resources to users who have access to them.
> Different users have access to subset of the same resources.

---

### Context-Dependant Access Control

> Restrict access to resources based on the state in which the user is in, such as performing actions in the wrong order.

---
