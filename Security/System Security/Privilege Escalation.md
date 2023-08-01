
### General Notes

> Increase privileges to root user.

---

### Looking for files with SUID permissions.

```
find / type -f -user root -perm -u=s 2> /dev/null
find / -perm /4000 2> /dev/null
```
> `2> /dev/null` discards of any errors.

> Go to [GTFObins](https://gtfobins.github.io/) to see how to escalate privileges.

---

