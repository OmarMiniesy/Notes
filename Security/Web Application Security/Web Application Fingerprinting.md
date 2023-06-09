
### General Notes

> Detecting the daemon providing the web server service.
> The version of the daemon.
> The operating system of the host machine.

---

## Tools Used

### `Netcat` for [[HTTP]]

> Can be used as both client and server.
> As client, send requests to the server and perform `banner grabbing`
> `banner grabbing` is done by connecting to the daemon and read the banner it sends the client.

> Pass the destination host and destination [[Port]]. The port is usually the default 80 for `HTTP`
> `nc <address> 80`

> An HTTP request is then sent using HTTP verbs.
> The request can look like:
> `HEAD / HTTP/1.0 ` which contains the verb, directory, and [[Protocol]] version.
>  Press enter 2 times (2 empty lines between head and body).

> Can use `-v` for verbosity to check out the status of the request and response.
> The HTTP verbs must be in capital letters.

### `openssl` for [[HTTPS]]

> establish connection with HTTPS service and send requests.
> Same way as `Netcat`, with the port usually being 443 for HTTPS.
> `openssl s_client -connect <address>:<port>`

### `httprint` 

> Uses a signature based technique to identify web servers.
> `httprint –P0 -h <targets> -s <signature file>`
> The `-P0` flag is to avoid pinging

---


