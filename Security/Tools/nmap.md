
### General Notes

> Tool used in [[Footprinting and Scanning]].
> Gathers information about [[Port]]s.

---
### Best Scripts

1. Script scan and version scan
```
nmap -sC -sV <ip-address>
```

---

### For [[Null Session]]s 

> Vulnerability affecting ports 137, 138, 139, 445 on windows machines.
> Access shares and get information about users/passwords.

> To enumerate shares use `--script=smb-enum-shares`.
> To enumerate users use `--script=smb-enum-users`.
> To brute force the user passwords use `--script=smb-brute`.
> To check vulnerabilities use `--script=smb-check-vulns`.

---
