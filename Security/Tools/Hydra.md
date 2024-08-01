
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

- Get detailed info about each module
```
hydra -U <protocol/module-name>
```

- To launch an attack against a service with a file containing usernames and a file for passwords.
```
hydra -L <userfile> -P <passfile> <service://server> <options>
```

- This command attacks logging-in in websites using the [[HTTP]] `POST` method. 
```
hydra <website> http-post-form "<login-path-file>:usr=^USER^&pwd=^PASS^:invalid credentials" -L share/ncrack/minimal.usr	-P share/seclists/Passwords/rockyou-15.txt -f -V
```
1. The username part has a name of `usr` and the password of `pwd`. `:invalid credentials` is what happens when the brute force trial fails, it is something special for the website.
2. `-f` to stop after first successful attempt.
3. `-V` for verbosity.

---
### Scripts

> Given a username and password wordlist to attack [[Secure Shell Protocol (SSH)]].

```
hydra -l <username> -P <wordlist> ssh://<ip-address>
```

---

