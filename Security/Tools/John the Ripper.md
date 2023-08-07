
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
### ssh2john

> If there is a private [[Secure Shell Protocol (SSH)]] key found, `id_rsa` and it is password protected.
> To know if it is password protected, open the file and check the header to see that it is encrypted.
> Use this tool to convert it to a format that john can crack to obtain the password.
```
ssh2john id_rsa > new_id_rsa.txt
```

> Then, use a normal dictionary attack to crack the password.
```
john --wordlist=<path-to-wordlist> new_id_rsa.txt
```

> Finally, we can then connect via SSH using the obtained password and present private key.
```
ssh -i id_rsa <username>@<ip-address>
```
> If that doesn't work, try setting the permissions of the `id_rsa` to read only.
```
chmod 600 id_rsa
```

---

### zip2john

> If there is a zip file that we try to extract its contents.
```
7z e <zipfile.zip>
```

> But we see that we need to enter a password, we use the `zip2john` tool to write to a new file that we can use `john` on.
```bash
zip2john <zipfile.zip> > newzip
```

> Now we use `john` to crack the password.
```
john --wordlist=<path-to-wordlist> newzip
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
