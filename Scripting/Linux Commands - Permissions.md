
A collection of some of the commands I found useful and convenient to use. Check the [[Linux Privilege Escalation]] file for scripts focusing more on security.

> The permissions of a file are displayed as a string of 10 characters. The first character is `d` for directories and `-` for files. The remaining 9 are `rwx` repeated 3 times. The first 3 are for the user owner, the middle 3 are for the group, and the final 3 are for all the users. If the permission is not granted, it is replaced by a `-`.

### Changing Permissions

- To change the owner of a file:
```bash
chown <user-name> <file-name>
```

- To change the group of a file:
```bash
chgrp <grp-name> <file-name>
```

- To change the permissions of a file:
```bash
chmod <user-perm><group_perm><others-perm> <filename>
```

> The permissions are integers from 0 to 7, and they represent in binary the permissions of `rwx`. If all are off, then it is 0, if all are granted then it is 7.

---
### Special Permissions

**SUID**: A permission bit that allows any user to execute the given file as the owner user.
**SGID**: A permission bit that allows any user to execute the given file as the owner group.

- To grant the SUID or SGID permissions for a file:
```bash
chmod 4<u><g><o> <filename>  # SUID
chmod 2<u><g><o> <filename>  # SGID
```

