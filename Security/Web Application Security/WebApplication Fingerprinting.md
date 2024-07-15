
### General Notes

Detecting the daemon providing the web server service.
- The version of the daemon.
- The operating system of the host machine.

---
## Tools Used

##### `Netcat` for [[HTTP]]

Can be used as both client and server.
- As client, send requests to the server and perform `banner grabbing`.

> `banner grabbing` is done by connecting to the daemon and read the banner it sends the client.

- Pass the destination host and destination [[Port]]. The port is usually the default 80 for `HTTP`
> `nc <address> 80`

- An HTTP request is then sent using [[HTTP]] verbs which contains the directory and [[Protocol]] version. There are two `\n` characters after the header.
```
HEAD / HTTP/1.0 

```

Can use `-v` for verbosity to check out the status of the request and response.

> The HTTP verbs must be in capital letters.

##### `openssl` for [[HTTPS]]

Establish connection with [[HTTPS]] service and send requests.
- Same way as `Netcat`, with the port usually being 443 for HTTPS.

```
openssl s_client -connect <address>:<port>
```

##### `httprint` 

Uses a signature based technique to identify web servers.
```
httprint –P0 -h <targets> -s <signature file>
```
- The `-P0` flag is to avoid pinging

##### nikto

This is a webserver scanner and a vulnerability assessment tool. Similar to Wappalyzer, it gives information on the website technology stack.
```
nikto -h <URL> -Tuning b
```

> `h` for host and `Tuning b` is for software identification.

##### Whatweb

Used to identify web technologies, including content management systems (CMS), blogging platforms, statistic/analytics packages, JavaScript libraries, web servers, and embedded devices.
```
whatweb -a3 <URL> -v
```

> `-a` defines aggression level, we choose 3.


##### WafW00f

Used to identify firewalls and other security mechanisms.
```
wafw00f -v -a <URL>
```
- `-a` scans all firewalls and doesn't stop after first match.

---


