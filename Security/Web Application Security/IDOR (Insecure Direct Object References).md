### General Notes

[[Access Control]] vulnerability where a web application exposes a direct path to an object or a resource that a user has access to or can control. (**Direct Object Reference**)
- This vulnerability is present when resources are located in static files on the server.
- These file names could be guessed or have their pattern cracked, so that attackers can access whichever files they want.

> This file name can be altered by an attacker to view other files for other users as well.

This vulnerability is usually the result of weak access control systems in the backend.
- The frontend restricts users from visiting resources by denying access to pages or [[Application Programming Interface (API)]] calls.
- If the users manage to bypass the frontend, and there isn't a secure system in the backend, the vulnerability arises.

> IDOR's main impact is having users access private files and resources that they do not have proper authorization to view.

---
### Identifying IDOR

There are many locations where **Direct Object References** can be found, or the static path that a file or resource is being passed.
##### URL Parameters and APIs

Study the [[HTTP]] request and identify any possible:
1. *headers*.
2. *cookies*. [[Cookies]].
3. *URL parameters* 
4. *API parameters* 

> These may contain object references.

##### AJAX Calls

These are basically JavaScript APIs that get called by the application.
- Study them and check if there are any parameters or APIs that have references to objects that can be tested for IDOR.

Sometimes there are APIs that are present in the frontend but are not called unless invoked by the correct user with the adequate role.
- Look into the frontend code and check if there are any functions present that can contain any direct object references.

##### Multiple Users

Try logging in with multiple users and try calling functions from the first user by passing the information of the second user.
- Monitor how the APIs are called from a user, and try making the same call from another user that shouldn't be able to perform it by duplicating parameters and their values.

---
### Exploiting IDOR

Once an IDOR vulnerability is located, basic techniques can be used to test it and see whether some data can be exposed.
- If the basic techniques don't work, then we need to better *understand the website*, how the *object references are calculated*, and how the *access control system works*.

##### Enumeration

Once a specific IDOR vulnerability is located, try using fuzzing tools like [[ffuf]] or brute force through [[Burp Suite]]'s intruder to enumerate and expose data belonging to other users.

> Try writing scrips that automate the process of calculating the value of the object reference using tools like [[cURL]]. 

---
### Preventing IDOR Vulnerabilities


---