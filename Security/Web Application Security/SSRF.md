### General Notes

SSRF or Server Side Request Forgery.
- An attacker makes the server send requests to different locations.
- Abuse server functionality to perform internal/external resource requests.

For example, the attacker causes the web server to make a connection with internal services inside the infrastructure, or connect to arbitrary external systems.

> This can cause leaks of sensitive data, and a main target is to achieve RCE through [[Reverse Shells]].

SSRF exploit trust relationships to escalate attacks from the web application.
- These trust relationships could be with the server itself, or to other back-end systems found in the organization.

To look for SSRF:
- Parts of [[HTTP]] requests, including URLs
- File imports such as HTML, PDFs, images, etc.
- Remote server connections to fetch data
- [Application Programming Interface (API)](Application%20Programming%20Interface%20(API).md) specification imports
- Dashboards including ping and similar functionalities to check server statuses

---
### Attacks

###### Attack Against Servers

Induce the application to make [[HTTP]] request back to the server hosting the application via an [[IP]] address that points back to it, such as `127.0.0.1` or `localhost`.
- Accessing pages from the server itself can sometimes bypass some [[Access Control]] functionalities.

> Modifying the URL that is taken by a backend *internal* [[Application Programming Interface (API)]] to something like `http://localhost/admin` can unlock the admin page, unlike visiting in the URL normally which would require credentials.

###### Attack Against Other Back-end Systems

 Application server can interact with other back-end systems not reachable by the user.
- They have private non reachable [[IP]] addresses.
- These backend systems have weak security and anyone who accesses them has access to sensitive functionality.

Similar to the attack against the server, try fetching an IP address from within the URL sent to the backend.
- Since this URL originates from there, it will have access to areas non-accessible by normal users.

---

### Bypassing Defenses

##### Blacklist-based input filters

- Applications can block `localhost` or `127.0.0.1`.
- They can also block important URLs such as `/admin`.

Alternatives: 
* Instead of `127.0.0.1`, use `2130706433`, `017700000001`, or `127.1`.
* Registering a domain that resolves to `127.0.0.1`.
* Using URL encoding to obfuscate blocked URL strings. [[Web Encoding]].
* Provide a URL that I control that redirects to the desired URL. 
	* Using different redirect codes.
	* Different [[Protocol]]s, ([[HTTP]] and [[HTTPS]]).

##### Whitelist-based input filters

Applications can sometimes only allow a predefined set of values.
- These can be bypassed by exploiting inconsistencies in URL parsing.

1. Embed credentials inside a URL before the hostname.
```
https://username@expected-host
```

2. Add URL fragments.
```
https://evil-host#expected-host
```

3. Abuse the [[Domain Name System (DNS)]] naming hierarchy to place input into a domain that i control.
```
https://expected-host.evil-host
```

4.  Using URL encoding and double encoding. [[Web Encoding]].

###### Open Redirection

If the value of a parameter is used to fetch another page.
- We can try playing with the value in that parameter, and make it fetch the page we desire with the path starting from localhost.

---
