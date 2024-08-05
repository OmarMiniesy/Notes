### General Notes

A useful tool for brute force attacks, fuzzing, and enumeration.

> [ffuf](https://github.com/ffuf/ffuf)

---
### Usage

###### 1. Subdomains

```
ffuf -u https://FUZZ.yahoo.com/ -w /usr/share/wordlists/seclists/Discovery/DNS/<wordlist> -p 1
```
- `-p` for delay between requests.

###### 2. Virtual Hosts ([[Virtual Hosting]]) 

Make sure to add the IP address into the `/etc/hosts` file.
```
ffuf -u https://yahoo.com/ -w /usr/share/wordlists/seclists/Discovery/DNS/<wordlist> -H 'Host: FUZZ.yahoo.com' -fs <size>
```
- We fuzz the `host` header using the `-H` flag.
- All responses will be `200 OK` since we are only changing the headers, but when a response returns and actual existing page, the size should be different.
- Use `-fs` the second time after it runs to filter out the repeated size.
###### 3. Directories

```
ffuf -u https://yahoo.com/FUZZ -w /usr/share/wordlists/dirb/common.txt -t 200
```
-  `-t` to use more threads to speed up the process.

To be recursive, so to discover directories within directories, use the `-recursion` flag and specify a `-recursion-depth x` value.
```
ffuf -u https://yahoo.com/FUZZ -w /usr/share/wordlists/dirb/common.txt -recursion -recursion-depth 1 -v
```
- `-v` for verbosity to print the path to the reached resource.
- Can add `-e` with extensions to look for more pages.

###### 4. Pages with Extensions

```
ffuf -u https://yahoo.com/indexFUZZ -w /usr/share/seclists/Discovery/Web-Content/web-extensions.txt
```
- This is if the page is known, but the extension isn't.

The extensions can also be shortened by figuring out the backend server by sending a `GET` request with `curl -i`.

```
ffuf -u https://yahoo.com/FUZZ -w /usr/share/wordlists/dirb/common.txt -e .php
```
- If the extensions are known but the pages aren't.
- This tries both no extensions and the `.php` extension.

These two approaches can be combined for a brute force attack if neither pages nor extensions are known; use 2 `FUZZ`.
```
ffuf -u https://yahoo.com/FUZZ1FUZZ2 -w /usr/share/wordlists/dirb/common.txt:FUZZ1 -w /usr/share/seclists/Discovery/Web-Content/web-extensions.txt:FUZZ2
```

###### 5. Parameters

Fuzz for parameters to check if any are published but not being used. This could open the door for more vulnerabilities.

> Add the IP address and the entire domain name in the `/etc/hosts` file before running. Could fix errors.

* `GET` query parameters.
```
ffuf -u https://yahoo.com?FUZZ=value -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt
```
> use `-fs` with size of the `200 OK` response to filter out the redundant responses.

* `POST` body parameters.
```
ffuf -u https://yahoo.com -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -d "FUZZ=value" -H "Content-Type: application/x-www-form-urlencoded" -X POST
```
> Add the parameters to the body using `-d`.
> Add the header `content-type: application/x-www-form-urlencoded` in the case of PHP.
> Add the `-x POST` to indicate a POST request.

After finding the parameter names, we can now fuzz for their values using a similar technique.

###### 6. Sensitive Files

Using `cewl`, we can scrape a website and take keywords:
```bash
cewl -m5 --lowercase -w <path-to-save> <url>
```
- `-m5` finds all words with minimum length of 5.
- `--lowercase` converts them all to lowercase.
- These words are then saved into the wordlist using `-w`.

Using ffuf, we can then try and fuzz for any files using this wordlist, in companionship with the `raft` SecLists wordlists for extensions, as well as the `wp-admin`, `wp-content`, `wp-includes` folders that might contain sensitive information.

```bash
ffuf -w /folders.txt:FOLDERS, /wordlist.txt:WORDLIST, /extensions.txt:EXTENSIONS -u http://yahoo.com/FOLDERS?WORDLISTEXTENSIONS
```
- Saving the folders, extensions, and wordlists above into these file names, we can fuzz for sensitive information on the website using them.

###### 7. Usernames

We can exploit the difference in error messages returned when a valid and an invalid username is entered.
```bash
ffuf -w <wordlist> -u <URL> -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "username=FUZZ&password=whatever" -fr "Invalid username"
```
- This is a `POST` request to a login form, so the data and headers must be added. Check section 5.
- The data `-d` parameters should be obtained from the target website, `username` and `password` are just examples.
- The `-fr` flag is used to filter out the string `Invalid username`.

---
