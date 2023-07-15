
### General Notes

> SSRF or Server Side Request Forgery.
> An attacker makes the server send requests to different locations.

> For example, the attacker causes the web server to make a connection with internal services inside the infrastructure, or connect to arbitrary external systems.
> This can cause leaks of sensitive data.

> SSRF exploit trust relationships to escalate attacks from the web application.
> These trust relationships could be with the server itself, or to other back-end systems found in the organization.

---

### Attacks

###### Attack Against Servers

> Induce the application to make [[HTTP]] request back to the server hosting the application via an [[IP]] address that points back to it, such as `127.0.0.1` or `localhost`.
> Accessing pages from the server itself can sometimes bypass some [[Access Control]] functionalities.

> Modifying the URL that is taken by a backend *internal* [[Application Programming Interface (API)]] to something like `http://localhost/admin` can unlock the admin page, unlike visiting in the URL normally which would require credentials.

###### Attack Against Other Back-end Systems

> Applications erver can interact with other back-end systems not reachable by the user.
> They have private non reachable [[IP]] addresses.
> These backend systems have weak security and anyone who accesses them has access to sensitive functionality.

> Similar to the attack against the server, try fetching an IP address from within the URL sent to the backend.
> Since this URL originates from there, it will have access to areas non-accessible by normal users.

---
