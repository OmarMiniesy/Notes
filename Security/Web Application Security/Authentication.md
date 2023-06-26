
### General Notes

> The process of verifying the identity of a user.

* Knowledge Factors: Something you know like a password.
* Possesion Factors: Something you have like a security token.
* Inherence Factors: Something you are like biometrics.

> Authentication is verifying that a user is who they claim to be.
> Authorization is verifying whether a user is allowed to do something.

---

### Password Attacks

> Against websites that have username-password based login mechanisms.


##### Brute Force Attacks

> Trial and error attempts to guess valid user credentials.
> While brute forcing, must pay attention to: 
1. Status Codes: [[HTTP]] response codes can be observed. Sometimes the right username gives a different response than a wrong username.
2. Error Messages: Returned error messages are sometimes different when both username *and* password are incorrect, not just one of them. Observe characters for spelling mistakes, and so on.
3. Response Times: Observe response times. Sometimes websites will check password only if username is correct, so the response time increases. Can be checked by entering really large passwords, to make the website take longer to respond.

> Can be done via [[Burp Suite]] Intruder.

---
