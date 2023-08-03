### General Notes

> Increase privileges to root user.

---
### Looking for files with SUID permissions.

```
find / -perm /4000 2> /dev/null
```
> `2> /dev/null` discards of any errors.

> Go to [GTFObins](https://gtfobins.github.io/) to see how to escalate privileges.

---
### Enumerate possible methods using Linpeas

> Check out the [READMe](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS) file on how to run.

---
