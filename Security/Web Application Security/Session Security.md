### General Notes

These are attacks that are related to the [[Sessions]] of users.
- A session is used to continuously identify users, such that already known information doesn't need to be retransmitted.
- A user on a web application is said to have a session such that it informs the servers about the identity of the user as the user interacts with the web application.
 
If an attacker manages to grab a hold of a user session, then the attacker can impersonate that user and perform actions acting as the user.

---
### Obtaining Session Identifiers

There are several ways to have access to session identifiers belonging to another user:
- Traffic sniffing using a tool like [[Wireshark]].
- [[Cross Site Scripting (XSS)]].
- Browser history.
- Log diving
- Access to a database with session information.

##### PHP Session IDs: `PHPSESSID`

The location where session IDs are saved on a PHP server is identified in the `PHP.ini` file in an entry called `session.save_path`.
- Therefore, the first step is identifying *where* the `PHP.ini` file is, and then checking the value of the `session.save_path` variable.
```bash
locate php.ini
cat /path/of/php.ini | grep "session.save_path"
```

The output of this command will tell us where the session identifiers are stored.
- The files in this directory are of the format: `sess_valueofphpsessid`.

##### Java Session IDs:


##### .NET Session IDs



---
### Session Hijacking

The attacker takes advantage of insecure session identifiers and finds a way to obtain them.
- The attacker then uses them to authenticate to the server and impersonate the victim.

---
### Session Fixation

This attack takes place when an attacker fixes a valid session ID and then tricks the victim to log into the web application with this fixed ID that the attacker knows and specifies.
- Once the user logs in with the previously known session, the attacker can then hijack that session, allowing the attacker to impersonate the victim user.

> The goal of session fixation is to reach session hijacking.

To perform this attack, there are 3 steps to follow:
1. *Obtain a valid session identifier*, which can be done authenticating as a user, or by simply opening the web application.
2. *Fixate this valid session identifier*, which is the case if the session value remains the same before and after logging in **AND** the session ID can be accepted from the URL query parameters or `POST` data parameters.
3. *Trick the victim into establishing a session using the fixed session ID*, which can be done by crafting a URL and making the victim click it, thus, the web application assigns the session value to that user.

##### Identifying Session Fixation

Check if there are any valid session identifier values **present in the URL**, and if its value is **propagated to a cookie** on the webpage.
- Try testing it by entering a random value in the parameter, and see if this value gets saved in the cookie. If that is the case, then there is the fixation vulnerability.

---
