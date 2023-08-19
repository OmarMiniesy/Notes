
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
gobuster dir -u http://<ip-address> -w /usr/share/wordlists/dirb/common.txt -x php
```

---
### `Dirbuster`

---

### `ffuf`

---
