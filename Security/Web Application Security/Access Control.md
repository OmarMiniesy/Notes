### General Notes

Access control is applying constraints on who can perform actions or access resources.
- Dependent on [[Authentication]] and [[Sessions]].
- There are *Vertical, Horizontal, and Context-Dependent* Access Controls.

**Vertical access controls** are those that restrict the access of resources based on the type of user.
- So different types of users have access to different types of resources.
- These are designed to enforce business policies.

**Horizontal access controls** are those that restrict the access of the same type of resources to only a specific user of the same user type.
- So one user cannot access the resources that belong to another user.

**Context-Dependent access controls** are those that restrict the access of resources based on the state that the user or the application.
- So users do not perform actions in wrong orders.

Another category of Access Control vulnerabilities is [[IDOR (Insecure Direct Object References)]].

---
### Broken Access Controls

Sometimes, there exist vulnerabilities in these access controls, allowing users to access resources or perform actions that they are not supposed to be able to do.
- **[[#Vertical Privilege Escalation]]**: User gaining access to functions that they are not permitted to access, such as non-admin user getting access to an admin page.
- **[[#Horizontal Privilege Escalation]]**: User gaining access to resources and functions that  belong to another user of the same type.
- **Horizontal to Vertical Privilege Escalation**: This is when horizontal privilege escalation is used to target a more privileged user.

---
### Vertical Privilege Escalation

This happens when applications do not properly protect sensitive functionality.
###### 1. Unprotected functionality

Trying to access the admin page through the URL directly, or by locating any disclosed information.

- Looking for sensitive unprotected pages.
```
https://insecure-website.com/admin
```

- Checking other locations if there is disclosed information, such as the `robots.txt`file.
```
https://insecure-website.com/robots.txt
```

Checking the JavaScript also can disclose sensitive information.
- The UI can change depending on the type of user, and this might be in the script.
- Check to see if there is any disclosed URLs or functions.

> Otherwise, the URL can be brute forced using a dictionary attack. [[Directory and File Enumeration]].

###### 2. Parameter-based Access Controls

Applications can determine the roles and rights at login by storing this data in user-controllable locations.
* Hidden body parameter.
* [[Cookies]].
* Query string parameters in the URL. (`?parameter=value`).

> User can modify these values and gain access to sensitive functionality.

###### 3. Platform Misconfiguration - Check [Lab 5](https://github.com/OmarMiniesy/Walkthroughs/blob/main/Portswigger/Access%20Control/Lab%205.md) and [Lab 6](https://github.com/OmarMiniesy/Walkthroughs/blob/main/Portswigger/Access%20Control/Lab%206.md)

Some applications restrict access to specific URLS and [[HTTP]] methods based on user role.
- Denies `POST` methods on the URL `/admin/deleteuser` to `manager` users.
```
DENY: POST, /admin/deleteUser, managers
```

These can be overridden using [[HTTP]] headers that contain the wanted page, and sending the `/` root path in the request header.
* `X-Original-URL: /admin/deleteUser`.
* `X-Rewrite-URL: /admin/deleteUser`.

Sometimes these rules can be bypassed by trying different [[HTTP]] methods (verbs).
- Trying `GET` instead of `POST`. 
- Do that using [[Burp Suite]] repeater change request method.

###### 4. URL-Matching Discrepancies

- **Inconsistent capitalization**: Treating the same endpoint but with different capitalization as 2 different endpoints.
- **Spring framework** `useSuffixPatternMatch`: Paths with any file extension are the same as paths without the file extensions.
- Adding a **trailing backslash** in the end could be regarded as 2 different endpoints.
 
> Trying to capitalize, add file extensions, and adding trailing backslashes could lead to the same endpoint but are regarded differently by the browser.

---
### Horizontal Privilege Escalation

If a user is able to gain access to the resources belonging to another user.
###### 1. Controlling URL Parameters

User entering a different value for `id` and the browser allowing it could allow the user to access the resources of the user with that `id`.
```
https://insecure-website.com/myaccount?id=123
```

###### 2. Using Globally Unique Identifiers (GUIDs)

Some applications use GUIDs to identify users.
- These GUIDs can be disclosed in different places in the application, such as messages or reviews.
- These can be used similar to [[#1. Controlling URL Parameters]].

> When these attacks fail, sometimes the website redirects. Checking the response for the redirect might contain sensitive data belonging to targeted user.

---
### `Referer` Based Access Control

Some websites base controls on the `Referer` header.
- It is added to requests to indicate the page from which the request initialized.
- Some applications only use the `Referer` header for pages after a secured one.

For the subpages of `/admin/`, such as `/admin/deleteUser`, the only check done by `/deleteUser` is the that the `referer` header contains `/admin`.
- Manipulating the `referer` header can help bypass security protections, and skip the intended sequence.

---
### Preventing Access Control Vulnerabilities

* Never rely on obfuscation only. (Patterns or long ids)
* Deny access to any resource not publicly available.
* Use a single application mechanism for enforcing control.
* All resources should have their access declared and by default denied.
* Thoroughly test access controls.

---
