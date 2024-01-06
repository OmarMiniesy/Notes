
### General Notes

> client URL.
> Command line tool that supports [[HTTP]], [[HTTPS]], and other [[Protocol]]s.
> Used to write scripts and automate sending requests and handling responses.

---

### Usage

* Send a basic [[HTTP]] request by giving its URL.
```bash
curl [options...] www.google.com
```

* To save the response into a file with the same name as the file in the path use `-O`. To choose the name of the output file use `-o`.
```bash
curl -O www.google.com/index.html
curl -o <file-name> www.google.com/index.html
```
> There needs to be a file name at the end of the URL for the default name to work.

* Add verbosity to view the request and response via the `-v` flag.
```bash
curl -v www.google.com
```

* See the response headers only via the `-I` flag. To see the whole response message including body and headers use the `-i` flag.
```bash
curl -I www.google.com
```

* To add our own custom headers to a request being sent, use the `-H` flag. Some headers have their own custom flags as well:
```bash
curl www.google.com -A 'Mozzila/5.0'
```
> This sets the user-agent.

---
### HTTPS

>If the SSL certificate is invalid or outdated, then cURL will not work properly for [[HTTPS]] URLs.
>This is to protect against the Man-in-the-Middle HTTP downgrade attack.

* To skip the HTTPS certificate check, use the `-k` flag.
```bash
curl -k https://twitter.com
```

---

