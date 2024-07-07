
### General Notes

Tool used in [[Footprinting and Scanning]].
- Gathers information about [[Port]]s.

---
### Best Scripts

1. Script scan and version scan
```
nmap -sC -sV <ip-address>
```

---

### For [[Null Session]]s 

Vulnerability affecting ports 137, 138, 139, 445 on windows machines.
- Access shares and get information about users/passwords.

1. To enumerate shares use `--script=smb-enum-shares`.
2. To enumerate users use `--script=smb-enum-users`.
3. To brute force the user passwords use `--script=smb-brute`.
4. To check vulnerabilities use `--script=smb-check-vulns`.

---

### Proxy Through [[Burp Suite]]

> Using the `--proxies` flag, we can choose the proxy of our choice.

```
nmap --proxies http://127.0.0.1:8080 <IP> -sC -sV
```

This sets the [[IP]] address and [[Port]] combination `127.0.0.1:8080` using [[HTTP]] as proxy, which is the exact combination used by [[Burp Suite]]. Therefore, we can view all requests and responses in [[Burp Suite]] for any inspection.

---
