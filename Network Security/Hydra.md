
### General Notes

> Similar to [[John the Ripper]] but for services requiring Network authentication.
* SSH
* Telnet
* Remote Desktop (RDP)
* SMB
* Cisco Auth
* FTP
* IMAP
* [[HTTP]] 

> Hydra has modules for each [[Protocol]] it attacks.

---

### Usage

> Get detailed info about each module
```
hydra -U <protocol/module-name>
```

> To launch an attack against a service with a file containing usernames and a file for passwords.
```
hydra -L <userfile> -P <passfile> <service://server> <options>
```

>This command attacks website using the http post methods to attack login. The username part has a name of `usr` and the password of `pwd`. `:invalid credentials` is what happens when the brute force trial fails, it is
  something special for the website.
```
hydra <website> http-post-form "<login-path-file>:usr=^USER^&pwd=^PASS^:invalid credentials" -L share/ncrack/minimal.usr	-P share/seclists/Passwords/rockyou-15.txt -f -V
```
> `-f` to stop after first successful attempt.
> `-V` for verbosity.

---
