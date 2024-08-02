
### General Notes

Similar to [[John the Ripper]] but for services requiring Network authentication.
* [[Secure Shell Protocol (SSH)]]
* Telnet
* Remote Desktop (RDP)
* SMB
* Cisco Auth
* [[File Transfer Protocol (FTP)]]
* IMAP
* [[HTTP]] 

> Hydra has modules for each [[Protocol]] it attacks.

---
### Usage

- To see all the available modules supported by Hydra:
```bash
hydra -h | grep "Supported services" | tr ":" "\n" | tr " " "\n" | column -e
```

- Get detailed info about each protocol or service that can be attacked.
```bash
hydra -U <module>
```

- Important flags:
```bash
-f  ##stop after finding first successful combination.
-u  ## trying all usernames on each password, not all passwords on each username.
-l  ## assigns a static username
-p  ## assigns a static password
```

- To launch an attack against a service with a file containing usernames and a file for passwords.
```bash
hydra -L <userfile> -P <passfile> <service://server> <options>
```
> To add a list that has both usernames and passwords separated by a `:`, use the `-C` flag.

---
### [[HTTP]] Focus

- To launch an attack against a web server using [[HTTP]] `GET` requests:
```bash
hydra -C <wordlist> <IP> -s <port> http-get <path>
```
> The [[Port]] is added using the `-s` flag, and to specify HTTP, we add the `http-get` along with the path of the webpage that defaults to `/`.

- To launch an attack against a login form that uses `POST` requests, we can use the `http-post-form` module:
```bash
hydra -C <wordlist> <IP> -s <port> http-post-form <path:user_parameter=^USER^&pass_parameter=^PASS^:F=<match_string>>
```
1. First add the path of the login page.
2. Then add the username parameter and the password parameter followed by the placeholders for them.
3. Finally after the `:`, add the match condition which is either `F` for failure or `S` for success. The failure means that hydra will notify the user if the string is **not found**, while success means that hydra will notify the user if the string is **found**.
4. We used here the `-C` for combined `username:password` list, but we can use any of the other flags such as `l, L ,p ,P`.

> The match string consists of HTML content, so thinking of the correct HTML string that will be found or not found is important to make sure that results are accurate, with no false positives.

---
