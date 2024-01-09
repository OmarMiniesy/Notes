
### General Notes

> Find hidden resources that contain information about new features, backup files, or notes.
> Backups are sometimes left on servers that contain [[IP]] addresses of backend databases or credentials to a new feature.
> Similar to [[Subdomain Enumeration]].

> Brute force attacks and Dictionary attacks.
> Dictionary attacks using `Dirbuster` and `Dirb` using wordlists.
> Common backup file names:
* `.bak`
* `.old`
* `.txt`
* `.xxx`

---
### `Dirb` tool

> `-X` flag for specifying extensions in a comma separated list.
> `-a` flag for user agent. [List of User Agents](https://useragentstring.com/pages/useragentstring.php)
> `-u` flag for logging in.
> `-H` flag to pass headers.

---
### `Gobuster`

> To enumerate a given IP address for directories with a given file type.
```
gobuster dir -u http://<ip-address> -w /usr/share/wordlists/dirb/common.txt -x php,cgi,html,js,css,py,sh,txt
```

---
### `Dirbuster`

Fast tool for enumeration using GUI.

---

### `ffuf`

###### 1. Directories

```
ffuf -u https://yahoo.com/FUZZ -w /usr/share/wordlists/dirb/common.txt -t 200
```

> `-t` to use more threads to speed up the process.

To be recursive, so to discover directories within diretories, use the `-recursion` flag and specify a `-recursion-depth x` value.
```
ffuf -u https://yahoo.com/FUZZ -w /usr/share/wordlists/dirb/common.txt -recursion -recursion-depth 1 -v
```
> `-v` for verbosity to print the path to the reached resource.
> Can add `-e` with extensions to look for more pages.

###### 2. Files and Extensions

```
ffuf -u https://yahoo.com/minsFUZZ -w /usr/share/seclists/Discovery/Web-Content/web-extensions.txt
```
> This is if the page is known, but the extension isn't.

The extensions can also be shortened by figuring out the backend server by sending a `GET` request with `curl -i`.

```
ffuf -u https://yahoo.com/FUZZ -w /usr/share/wordlists/dirb/common.txt -e .php
```
> If the extensions are known but the pages aren't.
> This tries both no extensions and the `.php` extension.

These two approaches can be combined for a brute force attack if neither pages nor extensions are known; use 2 `FUZZ`.
```
ffuf -u https://yahoo.com/FUZZ1FUZZ2 -w /usr/share/wordlists/dirb/common.txt:FUZZ1 -w /usr/share/seclists/Discovery/Web-Content/web-extensions.txt:FUZZ2
```


---
