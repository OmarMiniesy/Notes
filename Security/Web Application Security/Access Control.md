
### General Notes

Constraints on who can perform actions or access resources.
- Dependent on [[Authentication]] and [[Sessions]] management.

> Vertical, Horizontal, and Context-dependent access controls.

---
### Vertical Access Control

Mechanisms that restrict access to sensitive resources that aren't available to all users.
- Different types of users have access to different resources.
#### Vertical Privilege Escalation

User gaining access to functions that they are not permitted to access.
##### Methods:

###### 1. Unprotected functionality

Trying to access the admin page through the URL directly.

- Looking for sensitive unprotected pages.
```
https://insecure-website.com/admin
```

- If this doesn't work, browse to the `robots.txt` to check for the disclosed admin page.
```
https://insecure-website.com/robots.txt
```

> Otherwise, the URL can be brute forced using a dictionary attack. [[Directory and File Enumeration]].

Check JavaScript scripts to check if anything is disclosed there. Some websites use scripts to show different UI if the user is an admin.

###### 2. Parameter-based 

Applications can determine the roles and rights at login by storing this data in user-controllable locations.
* Hidden body parameter.
* [[Cookies]].
* Query string parameters in the URL. (`?parameter=value`).

> User can modify these values and gain admin functionality.

###### 3. Platform Misconfiguration

Some applications restrict access to specific URLS and [[HTTP]] methods based on user role.
- Denies `POST` methods on the URL `/admin/deleteuser` to `manager` users.
```
DENY: POST, /admin/deleteUser, managers
```

These can be overridden using [[HTTP]] headers.
* `X-Original-URL: /admin/deleteUser`.
* `X-Rewrite-URL: /admin/deleteUser`.

Sometimes these rules can be bypassed by trying different [[HTTP]] methods (verbs).
- Trying `GET` instead of `POST`. Do that using [[Burp Suite]] repeater change request method.

###### 4. URL-Matching

- **Inconsistent capitalization**: Treating the same endpoint but with different capitalization as 2 different endpoints.
- **Spring framework** `useSuffixPatternMatch`: Paths with any file extension are the same as paths without the file extensions.
- Adding a **trailing backslash** in the end could be regarded as 2 different endpoints.
 
> Trying to capitalize, add file extensions, and adding trailing backslashes could lead to the same endpoint but are regarded differently by the browser.

---
### Horizontal Access Control

Mechanisms that restrict access of resources to users who have access to them.
- Different users have access to subset of the same resources.
#### Horizontal Privilege Escalation

User gaining access to resources of another user.
###### 1. 
- Changing the parameters in the URL.
```
https://insecure-website.com/myaccount?id=123
```
> User entering a different value for `id` and the browser allowing it could allow for access to their resources.

###### 2.
Some applications use GUIDs to identify users. (Globally unique identifiers).
- These GUIDs can be disclosed in different places in the application, such as messages or reviews.

> These can be used in the `id` parameter.

###### 3. 
When these attacks fail, sometimes the website redirects.
- Checking the response for the redirect might contain sensitive data belonging to targeted user.

---
### Context-Dependent Access Control

Restrict access to resources based on the state in which the user is in, such as performing actions in the wrong order.

---
### `Referer` HTTP Header Control

Some websites base controls on the `Referer` header.
- It is added to requests to indicate the page from which the request initialized.
- Some applications only use the `Referer` header for pages after a secured one.

> For example the `/admin` page is very secure, but `/admin/delete` only uses the `Referer`. So an authorized user can add the `referer` header to access these unsecure but sensitive pages.

---
### Preventing Access Control Vulnerabilities

* Never rely on obfuscation only. (Patterns or long ids)
* Deny access to any resource not publically available.
* Use a single application mechanism for enforcing control.
* All resources should have their access declared and by defualt denied.
* Thoroughly test access controls.

---
