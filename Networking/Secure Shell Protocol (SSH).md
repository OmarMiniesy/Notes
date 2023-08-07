### General Notes

> Cryptographic network [[Protocol]] for operating network services.
> Operatoes on [[Port]] 22.

---
### Connecting to SSH

> Connecting via terminal to a given [[IP]] address.
```
ssh <username>@<ip-address>
```

### Specifying [[Port]]

> If SSH isn't on the default port, use the `-p` flag to add the port number.

```
ssh <username>@<ip-address> -p PORT
```

### id_rsa private key

> If the file `id_rsa` is found, this is a private key that can be used to connect to SSH.
```
ssh -i id_rsa <username>@<ip-address>
```

> If it is encrypted, follow the steps in [[John the Ripper#ssh2john]].
> It is encrypted if when reading the contents of the file we see in its header `proc-type: 4, encrypted`.

> The `id_rsa` must have read only permissions.
```
chmod 600 id_rsa
```

---

### Downloading Files

> To download or copy a file from an SSH machine to our attacking machine, use the `scp` command from the attacking machine.
```shell
scp <target-user>@<target-IP>:/path/to/file /where/to/download
```
> The `/path/to/fil` is where it resides on the target machine, and the `/where/to/download` is where to download it on the attacking machine.

---
