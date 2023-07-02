
### General Notes

> Password craking tool.
> Can launch brute force and dictionary attacks on a password database.
> Seclists is a good wordlist to use. 
> Uses parallelization -> very fast.

> Used on many encyrption formats.
> Can view them via:
```
john --list=formats
```

> Can use `hashcat` for GPU cracking.
> Can use `opchrack` for rainbow tables cracking.

---

### Using John on `/etc/passwd` and `/etc/shadow`

* #### Brute Force Attack

> The usernames and password hashes need to be in the same file. Call it `crackme`.
```
unshadow /etc/passwd /etc/shadow > crackme
```

> For a brute force attack on the unshadowed file, and on the required users only.
```
john -incremental -users:<user-list> crackme
```

> To display the passwords recovered on the unshadowed file.
```
john --show crackme

cat /root/.john/john.pot    //displays the cracked passwords.
```


* #### Dictionary Attack

> Specify a wordlist to use as the dictionary.
```
john -wordlist=<path-to-wordlist> <file-to-crack>

john -wordlist <file-to-crack>   //uses the default wordlist.
```

> To allow dictionary mangling (upper and lower cases are mixed).
```
john -wordlist=<path-to-wordlist> -rules <file-to-crack>
```

---

### Extra Info

>To get the hash methods used.
```
/etc/login.defs

grep -A 30 ENCRYT_METHOD /etc/login.defs
```

> To view previously cracked passwords for a specific hashing technique.
```
john --show -format=<hash-method> <filename>
```

---
