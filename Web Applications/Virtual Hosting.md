
### General Notes

> Virtual hosting is a method for hosting multiple domain names (with separate handling of each name) on a single server.

> This allows one server to share its resources, such as memory and processor cycles, without requiring all the services to be used by the same hostname.

> The web server checks the domain name provided in the Host header field of the [[HTTP]] request and sends a response according to that.

---

### Name Based Virtual Hosting

The service, website, or domain requested here differs based on the name. They all have the same [[IP]] address.

> On the server, they are differentiated using different folders and directories.
> We can access these different hosts by specifying in the [[HTTP]] request the `host` header.

---

### [[IP]] Based Virtual Hosting

The host machine has multiple network interfaces, with each interface having a different IP address.

---
### Resolving Hostnames to [[IP]] Addresses

> This happens when the hostname above is present but the web browser can't resolve the page.

> The `/etc/hosts` file is used to resolve hostnames to IP addresses.
> Add an entry with the IP and Hostname into this file.
```
echo "<IP> <hostname>" | sudo tee -a /etc/hosts
```

> This will resolve the hostname given by including a `Host` [[HTTP]] header containing this hostname in every request with the given IP address.

---
